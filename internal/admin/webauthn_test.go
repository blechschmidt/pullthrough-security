package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/webauthn"
)

// stubWebAuthn is a controllable WebAuthnController for the admin middleware and
// handler tests. It records the arguments the middleware passes so a test can
// assert the subject/action binding.
type stubWebAuthn struct {
	enabled      bool
	enforcing    bool
	protected    map[string]bool
	acceptToken  string
	lastSubject  string
	lastAction   string
	verifyCalls  int
	beginAssertC int
}

func (s *stubWebAuthn) Enabled() bool                { return s.enabled }
func (s *stubWebAuthn) Enforcing() bool              { return s.enforcing }
func (s *stubWebAuthn) StepUpRequired(p string) bool { return s.enforcing && s.protected[p] }

func (s *stubWebAuthn) VerifyStepUp(_ context.Context, subject, action, token, _ string) error {
	s.verifyCalls++
	s.lastSubject = subject
	s.lastAction = action
	if token == s.acceptToken && token != "" {
		return nil
	}
	return webauthn.ErrStepUpRequired
}

func (s *stubWebAuthn) BeginRegistration(subject, _ string) (webauthn.RegistrationChallenge, error) {
	return webauthn.RegistrationChallenge{Challenge: "reg-chal", RPID: "example.com", UserName: subject}, nil
}

func (s *stubWebAuthn) FinishRegistration(_ context.Context, subject string, _ webauthn.RegistrationResponse) (webauthn.CredentialView, error) {
	return webauthn.CredentialView{ID: "cred-1", Label: "test"}, nil
}

func (s *stubWebAuthn) BeginAssertion(subject, action string) (webauthn.AssertionChallenge, error) {
	s.beginAssertC++
	s.lastSubject = subject
	s.lastAction = action
	return webauthn.AssertionChallenge{Challenge: "assert-chal", RPID: "example.com", Action: action}, nil
}

func (s *stubWebAuthn) FinishAssertion(_ context.Context, _ string, _ webauthn.AssertionResponse) (webauthn.StepUpResult, error) {
	return webauthn.StepUpResult{Token: s.acceptToken}, nil
}

func (s *stubWebAuthn) Credentials(string) []webauthn.CredentialView {
	return []webauthn.CredentialView{{ID: "cred-1", Label: "test"}}
}

func (s *stubWebAuthn) RemoveCredential(context.Context, string, string) (bool, error) {
	return true, nil
}

func (s *stubWebAuthn) Status() webauthn.Status {
	return webauthn.Status{Enabled: s.enabled, Enforcing: s.enforcing, RPID: "example.com"}
}

func newStepUpServer(t *testing.T, rec *recordingAudit, wa WebAuthnController) *Server {
	t.Helper()
	svc, err := adminauth.New(adminauth.Options{
		Prefix: "/admin",
		StaticTokens: []adminauth.StaticToken{
			{Name: "admin-user", Roles: []string{"admin"}, Secret: "admin-token-abcdef0123456789xyz"},
			{Name: "approver-user", Roles: []string{"approver"}, Secret: "approver-token-abcdef0123456789"},
		},
	})
	if err != nil {
		t.Fatalf("adminauth.New: %v", err)
	}
	srv, err := New(Options{
		Cache:     &fakeCache{},
		AdminAuth: svc,
		AuditLog:  rec,
		WebAuthn:  wa,
	})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	return srv
}

const (
	adminTok    = "admin-token-abcdef0123456789xyz"
	approverTok = "approver-token-abcdef0123456789"
)

// TestStepUpEnforcement verifies the middleware blocks a protected mutation
// without a fresh step-up token and admits it with one.
func TestStepUpEnforcement(t *testing.T) {
	wa := &stubWebAuthn{
		enabled:     true,
		enforcing:   true,
		protected:   map[string]bool{"/api/keys/rotate": true, "/api/lockdown/engage": true},
		acceptToken: "fresh-token",
	}
	rec := &recordingAudit{}
	h := newStepUpServer(t, rec, wa).Handler()

	do := func(method, path, token, stepUp string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		if stepUp != "" {
			r.Header.Set(StepUpTokenHeader, stepUp)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	// Protected endpoint, admin role, NO step-up token → 401 + X-StepUp-Required.
	w := do(http.MethodPost, "/admin/api/keys/rotate", adminTok, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no step-up token: code = %d, want 401", w.Code)
	}
	if w.Header().Get(StepUpRequiredHeader) != "webauthn" {
		t.Fatalf("missing X-StepUp-Required header: %q", w.Header().Get(StepUpRequiredHeader))
	}
	if wa.lastSubject != "admin-user" || wa.lastAction != "/api/keys/rotate" {
		t.Fatalf("step-up bound to subject=%q action=%q", wa.lastSubject, wa.lastAction)
	}

	// Protected endpoint WITH a valid step-up token → middleware admits it and
	// hands off to the handler (which returns 404 because no KeyRotation
	// controller is wired — proving we got past the step-up gate, not a 401).
	w = do(http.MethodPost, "/admin/api/keys/rotate", adminTok, "fresh-token")
	if w.Code == http.StatusUnauthorized {
		t.Fatalf("valid step-up token still blocked: code = %d", w.Code)
	}
	if w.Header().Get(StepUpRequiredHeader) != "" {
		t.Fatalf("X-StepUp-Required set on an admitted request")
	}

	// An unprotected mutation (not in the protected set) is NOT gated.
	before := wa.verifyCalls
	_ = do(http.MethodGet, "/admin/api/overview", adminTok, "")
	if wa.verifyCalls != before {
		t.Fatalf("overview GET triggered a step-up verification")
	}
}

// TestStepUpNotEnforcedWhenDisabled verifies a non-enforcing subsystem does not
// gate protected endpoints.
func TestStepUpNotEnforcedWhenDisabled(t *testing.T) {
	wa := &stubWebAuthn{enabled: true, enforcing: false, protected: map[string]bool{"/api/keys/rotate": true}}
	rec := &recordingAudit{}
	h := newStepUpServer(t, rec, wa).Handler()

	r := httptest.NewRequest(http.MethodPost, "/admin/api/keys/rotate", nil)
	r.Header.Set("Authorization", "Bearer "+adminTok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == http.StatusUnauthorized && w.Header().Get(StepUpRequiredHeader) != "" {
		t.Fatalf("non-enforcing subsystem gated the endpoint")
	}
	if wa.verifyCalls != 0 {
		t.Fatalf("non-enforcing subsystem ran a step-up verification")
	}
}

// TestWebAuthnCeremonyEndpoints smoke-tests the enrolment/assertion handlers and
// confirms they are self-service (reachable by a non-admin approver) and are
// themselves never step-up-gated.
func TestWebAuthnCeremonyEndpoints(t *testing.T) {
	wa := &stubWebAuthn{
		enabled:     true,
		enforcing:   true,
		protected:   map[string]bool{"/api/approvals/approve": true},
		acceptToken: "fresh-token",
	}
	rec := &recordingAudit{}
	h := newStepUpServer(t, rec, wa).Handler()

	call := func(method, path, token, body string) *httptest.ResponseRecorder {
		var r *http.Request
		if body != "" {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	// Status is readable.
	if w := call(http.MethodGet, "/admin/api/webauthn", approverTok, ""); w.Code != http.StatusOK {
		t.Fatalf("GET /api/webauthn = %d, want 200", w.Code)
	}
	// Assertion begin must be reachable WITHOUT a step-up token (it is how a token
	// is obtained) even though it is a POST.
	if w := call(http.MethodPost, "/admin/api/webauthn/assert/begin", approverTok, `{"action":"/api/approvals/approve"}`); w.Code != http.StatusOK {
		t.Fatalf("assert/begin = %d, want 200", w.Code)
	}
	if wa.lastAction != "/api/approvals/approve" {
		t.Fatalf("assert begin action = %q", wa.lastAction)
	}
	// Registration begin reachable by a non-admin (self-service).
	if w := call(http.MethodPost, "/admin/api/webauthn/register/begin", approverTok, ""); w.Code != http.StatusOK {
		t.Fatalf("register/begin = %d, want 200", w.Code)
	}
}

func TestWebAuthnCeremonyCapabilities(t *testing.T) {
	paths := []string{
		"/api/webauthn/register/begin",
		"/api/webauthn/register/finish",
		"/api/webauthn/assert/begin",
		"/api/webauthn/assert/finish",
		"/api/webauthn/credential",
	}
	for _, p := range paths {
		if got := requiredCapability(http.MethodPost, p); got != adminauth.CapRead {
			t.Errorf("requiredCapability(POST %s) = %v, want CapRead", p, got)
		}
	}
	// The protected key-rotation mutation still maps to an operational capability.
	if got := requiredCapability(http.MethodPost, "/api/keys/rotate"); got != adminauth.CapOperate {
		t.Errorf("keys/rotate cap = %v, want CapOperate", got)
	}
}
