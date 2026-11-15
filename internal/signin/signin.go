// Package signin lets several OpenID Connect sign-ins of the proxy share the
// redirect URI an identity provider sends the browser back to.
//
// The admin console (internal/adminauth) and the personal-links page
// (internal/userlinks) each run an authorization-code sign-in, and each serves
// its callback under its own path by default. A provider registration often
// cannot be changed at will, though, and one that already lists a callback for
// the proxy's origin should be usable as it is: both sign-ins may be configured
// with the same redirect URL. The gateway then serves that path once, through
// Routes, and hands each request to the sign-in it answers — the one whose
// login-state cookie matches the request's state parameter.
package signin

import (
	"net/http"
	"sort"
)

// State is what a request that came back from an identity provider says about
// one sign-in flow.
type State int

const (
	// Absent: the request carries no login state of this flow.
	Absent State = iota
	// Foreign: it carries this flow's login state, but the state does not
	// answer the request — it is stale, tampered with, or belongs to another
	// sign-in of the same browser.
	Foreign
	// Matches: the request answers a sign-in this flow started.
	Matches
)

// Callback is a sign-in flow that the identity provider sends back to the
// proxy.
type Callback interface {
	// CallbackRoute is the path the gateway must serve the callback at, or ""
	// when the flow's own surface serves it (its default callback path).
	CallbackRoute() string
	// CallbackState reports what r says about this flow's sign-in.
	CallbackState(r *http.Request) State
	// HandleCallback completes the sign-in r answers.
	HandleCallback(w http.ResponseWriter, r *http.Request)
}

// Routes returns the handlers the gateway mounts for the given callbacks: one
// per route, keyed by path. A callback with no route of its own is left out;
// nil entries are skipped.
func Routes(callbacks ...Callback) map[string]http.Handler {
	byRoute := map[string][]Callback{}
	var order []string
	for _, cb := range callbacks {
		if cb == nil {
			continue
		}
		route := cb.CallbackRoute()
		if route == "" {
			continue
		}
		if _, seen := byRoute[route]; !seen {
			order = append(order, route)
		}
		byRoute[route] = append(byRoute[route], cb)
	}
	sort.Strings(order)
	out := make(map[string]http.Handler, len(order))
	for _, route := range order {
		out[route] = dispatcher(byRoute[route])
	}
	return out
}

// dispatcher hands a callback request to the flow it answers: the first whose
// state matches; failing that, the first that has state on the request at all,
// so the user sees the error page of the sign-in they started; failing that,
// the first flow, which explains that no sign-in was started here.
type dispatcher []Callback

func (d dispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var foreign Callback
	for _, cb := range d {
		switch cb.CallbackState(r) {
		case Matches:
			cb.HandleCallback(w, r)
			return
		case Foreign:
			if foreign == nil {
				foreign = cb
			}
		}
	}
	if foreign != nil {
		foreign.HandleCallback(w, r)
		return
	}
	d[0].HandleCallback(w, r)
}
