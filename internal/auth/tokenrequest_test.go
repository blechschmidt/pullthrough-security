package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// entraTokenEndpoint is a token endpoint with Microsoft Entra ID's rule on
// cross-origin redemption: spa says whether the redirect URI is registered as
// a single-page application. It records the Origin of every request.
type entraTokenEndpoint struct {
	mu      sync.Mutex
	spa     bool
	origins []string
	basic   []bool
}

func (e *entraTokenEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	origin := r.Header.Get("Origin")
	e.origins = append(e.origins, origin)
	_, _, basic := r.BasicAuth()
	e.basic = append(e.basic, basic)
	spa := e.spa
	e.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.ParseForm() != nil || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("code") == "":
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
	case spa && origin == "":
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"AADSTS9002327: Tokens issued for the 'Single-Page Application' client-type may only be redeemed via cross-origin requests. Trace ID: x","error_codes":[9002327]}`))
	case !spa && origin != "":
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"AADSTS9002326: Cross-origin token redemption is permitted only for the 'Single-Page Application' client-type.","error_codes":[9002326]}`))
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": "a.b.c", "access_token": "at", "token_type": "Bearer"})
	}
}

func (e *entraTokenEndpoint) setSPA(spa bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.spa = spa
}

func (e *entraTokenEndpoint) takeOrigins() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.origins
	e.origins = nil
	return out
}

func redemption(endpoint string) CodeRedemption {
	return CodeRedemption{
		TokenEndpoint: endpoint,
		Code:          "code-1",
		Verifier:      "verifier",
		RedirectURL:   "https://proxy.example.com:8889/auth/oidc",
		ClientID:      "client-1",
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A public client whose redirect URI Entra registered as a single-page
// application is refused without an Origin; it asks again with the origin of
// its redirect URI, and from then on sends it first.
func TestCodeRedeemerEntraSinglePageApplication(t *testing.T) {
	ep := &entraTokenEndpoint{spa: true}
	srv := httptest.NewServer(ep)
	defer srv.Close()
	var rd CodeRedeemer

	tr, err := rd.Redeem(context.Background(), redemption(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if tr.StatusCode != http.StatusOK || tr.IDToken != "a.b.c" || !tr.CrossOrigin {
		t.Fatalf("answer = %+v", tr)
	}
	if got, want := ep.takeOrigins(), []string{"", "https://proxy.example.com:8889"}; !sameStrings(got, want) {
		t.Fatalf("origins = %q, want %q", got, want)
	}

	// Learned: the next redemption needs one request.
	if tr, err = rd.Redeem(context.Background(), redemption(srv.URL)); err != nil || tr.IDToken == "" {
		t.Fatalf("second redemption: %+v %v", tr, err)
	}
	if got, want := ep.takeOrigins(), []string{"https://proxy.example.com:8889"}; !sameStrings(got, want) {
		t.Fatalf("origins = %q, want %q", got, want)
	}

	// The registration moves to the Web or desktop platform: Entra now refuses
	// the Origin, and the redeemer drops it again.
	ep.setSPA(false)
	if tr, err = rd.Redeem(context.Background(), redemption(srv.URL)); err != nil || tr.IDToken == "" || tr.CrossOrigin {
		t.Fatalf("after the platform change: %+v %v", tr, err)
	}
	if got, want := ep.takeOrigins(), []string{"https://proxy.example.com:8889", ""}; !sameStrings(got, want) {
		t.Fatalf("origins = %q, want %q", got, want)
	}
	if tr, err = rd.Redeem(context.Background(), redemption(srv.URL)); err != nil || tr.IDToken == "" {
		t.Fatalf("redemption after unlearning: %+v %v", tr, err)
	}
	if got, want := ep.takeOrigins(), []string{""}; !sameStrings(got, want) {
		t.Fatalf("origins = %q, want %q", got, want)
	}
}

// No Origin header is ever sent before the provider asked for one: a Web or
// desktop registration refuses it.
func TestCodeRedeemerSendsNoOriginUnasked(t *testing.T) {
	ep := &entraTokenEndpoint{}
	srv := httptest.NewServer(ep)
	defer srv.Close()
	var rd CodeRedeemer
	for i := 0; i < 2; i++ {
		tr, err := rd.Redeem(context.Background(), redemption(srv.URL))
		if err != nil || tr.StatusCode != http.StatusOK || tr.CrossOrigin {
			t.Fatalf("redemption %d: %+v %v", i, tr, err)
		}
	}
	if got := ep.takeOrigins(); !sameStrings(got, []string{"", ""}) {
		t.Fatalf("origins = %q", got)
	}
}

// A confidential client is never retried cross-origin: Entra accepts no
// client secret there, and the refusal is the caller's to report.
func TestCodeRedeemerConfidentialClientIsNotRetried(t *testing.T) {
	ep := &entraTokenEndpoint{spa: true}
	srv := httptest.NewServer(ep)
	defer srv.Close()
	req := redemption(srv.URL)
	req.ClientSecret = "s3cret~with.chars"
	var rd CodeRedeemer
	tr, err := rd.Redeem(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Error != "invalid_request" || !tr.hasEntraCode(9002327) || tr.CrossOrigin {
		t.Fatalf("answer = %+v", tr)
	}
	if got := ep.takeOrigins(); !sameStrings(got, []string{""}) {
		t.Fatalf("origins = %q", got)
	}
	if len(ep.basic) != 1 || !ep.basic[0] {
		t.Fatalf("the secret was not sent with HTTP Basic: %v", ep.basic)
	}
}

// Another provider's refusal is returned as it is, after one request; an
// answer that is not JSON is an error.
func TestCodeRedeemerOtherRefusalsAndGarbage(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if strings.HasSuffix(r.URL.Path, "/garbage") {
			_, _ = w.Write([]byte("<html>gateway timeout</html>"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"code expired"}`))
	}))
	defer srv.Close()
	var rd CodeRedeemer
	tr, err := rd.Redeem(context.Background(), redemption(srv.URL+"/token"))
	if err != nil || tr.Error != "invalid_grant" || tr.StatusCode != http.StatusBadRequest || calls != 1 {
		t.Fatalf("answer = %+v, err = %v, calls = %d", tr, err, calls)
	}
	if _, err := rd.Redeem(context.Background(), redemption(srv.URL+"/garbage")); err == nil || !strings.Contains(err.Error(), "not JSON") {
		t.Fatalf("garbage answer: err = %v", err)
	}
}

// The error of a discovery document for another issuer tells the operator how
// to configure an alias such as Entra's tenant domain.
func TestIssuerMismatchExplainsTheAlias(t *testing.T) {
	err := IssuerMismatch("https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0/.well-known/openid-configuration",
		"https://login.microsoftonline.com/0000-tenant/v2.0", "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0")
	msg := err.Error()
	for _, want := range []string{
		`set issuer to "https://login.microsoftonline.com/0000-tenant/v2.0"`,
		`discoveryUrl to "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0/.well-known/openid-configuration"`,
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q lacks %q", msg, want)
		}
	}
}
