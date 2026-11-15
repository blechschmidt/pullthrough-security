package main

import (
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/signin"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks"
)

// signInCallbacks returns the OpenID Connect sign-in callbacks the gateway
// serves at its root: those of the admin console and of the personal-links
// page whose redirect URL is not the surface's own callback path. The two may
// share one path — one redirect URI registered at the identity provider serves
// both sign-ins. Either service may be nil.
func signInCallbacks(adminAuth *adminauth.Service, links *userlinks.Service) map[string]http.Handler {
	var callbacks []signin.Callback
	if adminAuth != nil && adminAuth.OIDCEnabled() {
		callbacks = append(callbacks, adminAuth)
	}
	if links != nil && links.SignInEnabled() {
		callbacks = append(callbacks, links)
	}
	routes := signin.Routes(callbacks...)
	if len(routes) == 0 {
		return nil
	}
	return routes
}
