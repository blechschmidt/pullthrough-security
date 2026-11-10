package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/webauthn"
)

// WebAuthnController is the WebAuthn/passkey step-up surface the admin API
// exposes (Task 161): the subsystem read-model, the two ceremonies (registration
// and assertion), credential management, and the enforcement hook the RBAC
// middleware calls to gate a protected mutation. *webauthn.Service satisfies it.
type WebAuthnController interface {
	Enabled() bool
	Enforcing() bool
	StepUpRequired(relPath string) bool
	VerifyStepUp(ctx context.Context, subject, action, token, remoteAddr string) error
	BeginRegistration(subject, userName string) (webauthn.RegistrationChallenge, error)
	FinishRegistration(ctx context.Context, subject string, in webauthn.RegistrationResponse) (webauthn.CredentialView, error)
	BeginAssertion(subject, action string) (webauthn.AssertionChallenge, error)
	FinishAssertion(ctx context.Context, subject string, in webauthn.AssertionResponse) (webauthn.StepUpResult, error)
	Credentials(subject string) []webauthn.CredentialView
	RemoveCredential(ctx context.Context, subject, credID string) (bool, error)
	Status() webauthn.Status
}

// StepUpTokenHeader is the request header carrying a fresh step-up assertion
// token on a protected mutation.
const StepUpTokenHeader = "X-StepUp-Token"

// StepUpRequiredHeader is set on a 401 response when a protected endpoint needs
// a fresh step-up assertion, so the SPA knows to run the assertion ceremony and
// retry rather than prompting for a bearer token.
const StepUpRequiredHeader = "X-StepUp-Required"

// webAuthnStatusResponse is the GET /api/webauthn payload: the subsystem status
// plus the calling identity's registered credentials.
type webAuthnStatusResponse struct {
	webauthn.Status
	Subject     string                    `json:"subject"`
	Credentials []webauthn.CredentialView `json:"credentials"`
}

func (s *Server) webAuthnEnabled(w http.ResponseWriter) bool {
	if s.opts.WebAuthn == nil || !s.opts.WebAuthn.Enabled() {
		s.writeError(w, http.StatusNotFound, "webauthn step-up is not enabled")
		return false
	}
	return true
}

// handleWebAuthnStatus serves the subsystem read-model and the caller's own
// registered passkeys. When the subsystem is disabled it returns a benign
// disabled status (200) so the dashboard can hide the tab gracefully.
func (s *Server) handleWebAuthnStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.WebAuthn == nil || !s.opts.WebAuthn.Enabled() {
		s.writeJSON(w, http.StatusOK, webAuthnStatusResponse{
			Status:      webauthn.Status{Enabled: false},
			Credentials: []webauthn.CredentialView{},
		})
		return
	}
	subject := actorSubject(r)
	creds := s.opts.WebAuthn.Credentials(subject)
	if creds == nil {
		creds = []webauthn.CredentialView{}
	}
	s.writeJSON(w, http.StatusOK, webAuthnStatusResponse{
		Status:      s.opts.WebAuthn.Status(),
		Subject:     subject,
		Credentials: creds,
	})
}

// handleWebAuthnRegisterBegin issues a registration challenge for the caller.
func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if !s.webAuthnEnabled(w) {
		return
	}
	subject := actorSubject(r)
	challenge, err := s.opts.WebAuthn.BeginRegistration(subject, subject)
	if err != nil {
		s.writeWebAuthnError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, challenge)
}

// handleWebAuthnRegisterFinish verifies a registration response and stores the
// resulting credential for the caller.
func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if !s.webAuthnEnabled(w) {
		return
	}
	var in webauthn.RegistrationResponse
	if !s.decodeJSON(w, r, 64*1024, &in) {
		return
	}
	subject := actorSubject(r)
	view, err := s.opts.WebAuthn.FinishRegistration(r.Context(), subject, in)
	if err != nil {
		s.writeWebAuthnError(w, err)
		return
	}
	s.logger.Info("admin: passkey enrolled", "subject", subject, "credentialId", view.ID)
	s.writeJSON(w, http.StatusOK, view)
}

// webAuthnAssertBeginRequest optionally scopes the assertion to a protected
// action so the minted token is bound to it.
type webAuthnAssertBeginRequest struct {
	Action string `json:"action"`
}

// handleWebAuthnAssertBegin issues an assertion (step-up) challenge for the
// caller, optionally bound to a specific protected action.
func (s *Server) handleWebAuthnAssertBegin(w http.ResponseWriter, r *http.Request) {
	if !s.webAuthnEnabled(w) {
		return
	}
	var req webAuthnAssertBeginRequest
	// Tolerate an empty body (unscoped assertion).
	if r.ContentLength != 0 {
		if !s.decodeJSON(w, r, 8*1024, &req) {
			return
		}
	}
	subject := actorSubject(r)
	challenge, err := s.opts.WebAuthn.BeginAssertion(subject, req.Action)
	if err != nil {
		s.writeWebAuthnError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, challenge)
}

// handleWebAuthnAssertFinish verifies an assertion and returns a fresh step-up
// token the SPA attaches to the subsequent protected mutation.
func (s *Server) handleWebAuthnAssertFinish(w http.ResponseWriter, r *http.Request) {
	if !s.webAuthnEnabled(w) {
		return
	}
	var in webauthn.AssertionResponse
	if !s.decodeJSON(w, r, 64*1024, &in) {
		return
	}
	subject := actorSubject(r)
	res, err := s.opts.WebAuthn.FinishAssertion(r.Context(), subject, in)
	if err != nil {
		s.writeWebAuthnError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, res)
}

// handleWebAuthnRemoveCredential deletes one of the caller's own passkeys.
func (s *Server) handleWebAuthnRemoveCredential(w http.ResponseWriter, r *http.Request) {
	if !s.webAuthnEnabled(w) {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "missing credential id")
		return
	}
	subject := actorSubject(r)
	ok, err := s.opts.WebAuthn.RemoveCredential(r.Context(), subject, id)
	if err != nil {
		s.writeWebAuthnError(w, err)
		return
	}
	if !ok {
		s.writeError(w, http.StatusNotFound, "credential not found")
		return
	}
	s.logger.Info("admin: passkey removed", "subject", subject, "credentialId", id)
	s.writeJSON(w, http.StatusOK, map[string]any{"removed": true, "id": id})
}

// writeWebAuthnError maps the subsystem's typed errors to HTTP status codes.
func (s *Server) writeWebAuthnError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, webauthn.ErrDisabled):
		s.writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, webauthn.ErrNoCredentials):
		s.writeError(w, http.StatusBadRequest, "no passkey is registered for this identity; enroll one first")
	case errors.Is(err, webauthn.ErrChallengeExpired),
		errors.Is(err, webauthn.ErrChallengeMismatch),
		errors.Is(err, webauthn.ErrBadOrigin),
		errors.Is(err, webauthn.ErrUnknownCredential),
		errors.Is(err, webauthn.ErrCounterRollback):
		s.writeError(w, http.StatusBadRequest, err.Error())
	default:
		s.writeError(w, http.StatusBadRequest, err.Error())
	}
}
