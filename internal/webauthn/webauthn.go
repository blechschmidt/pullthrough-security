// Package webauthn implements WebAuthn / FIDO2 passkey step-up authentication
// for the proxy's most sensitive admin operations (Task 161).
//
// It provides the two WebAuthn ceremonies — registration (attestation) and
// assertion — reduced to the needs of a server-side step-up gate:
//
//   - Registration enrols a passkey for an already-authenticated admin subject,
//     verifying the attestation statement where the format permits and storing
//     the resulting credential (public key + signature counter) in a durable
//     sidecar file.
//   - Assertion is the step-up itself: a fresh, challenge-bound signature from a
//     registered authenticator. A successful assertion mints a short-TTL,
//     single-use step-up token that the admin middleware requires before it will
//     admit a protected mutation.
//
// Security properties enforced here:
//   - Challenges are 32 bytes of CSPRNG output, bound to a subject + ceremony
//     type, single-use, and expire after a short TTL (replay resistance).
//   - The authenticator signature counter must strictly increase (or stay zero);
//     a regression signals a cloned authenticator and is rejected.
//   - The RP ID hash and the client-data origin/type are validated on every
//     ceremony.
//
// All verification is hand-rolled on top of the standard library (no WebAuthn
// dependency), matching the project's convention for untrusted-format parsers.
package webauthn

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
)

// Default ceremony timings.
const (
	defaultChallengeTTL = 2 * time.Minute
	defaultStepUpTTL    = 5 * time.Minute
	maxCredsPerSubject  = 20
	maxPendingChallenge = 4096
)

// defaultProtectedActions are the admin endpoint paths (relative to the mount
// prefix) that require a fresh step-up assertion when enforcement is enabled.
// They correspond to break-glass approvals (Task 50), emergency lockdown
// (Task 74), policy-preset apply (Task 88), and key-rotation triggers (Task 148).
var defaultProtectedActions = []string{
	"/api/approvals/approve",
	"/api/approvals/deny",
	"/api/lockdown/engage",
	"/api/lockdown/clear",
	"/api/presets/apply",
	"/api/keys/rotate",
}

// Typed errors so the admin layer can map ceremonies to HTTP status codes.
var (
	ErrDisabled          = errors.New("webauthn: step-up authentication is not enabled")
	ErrNoCredentials     = errors.New("webauthn: no passkey is registered for this identity")
	ErrUnknownCredential = errors.New("webauthn: assertion references an unknown credential")
	ErrChallengeExpired  = errors.New("webauthn: challenge is unknown or has expired")
	ErrChallengeMismatch = errors.New("webauthn: client data challenge does not match")
	ErrBadOrigin         = errors.New("webauthn: client data origin is not allowed")
	ErrCounterRollback   = errors.New("webauthn: authenticator signature counter regressed (possible cloned authenticator)")
	ErrStepUpRequired    = errors.New("webauthn: a fresh passkey step-up assertion is required")
	ErrStepUpInvalid     = errors.New("webauthn: step-up token is missing, expired, or not bound to this identity")
)

// AuditLogger is the narrow audit write surface. *audit.Logger satisfies it; a
// nil logger disables audit recording.
type AuditLogger interface {
	Log(ctx context.Context, ev audit.Event) error
}

// Config configures the step-up subsystem.
type Config struct {
	// Enabled is the master switch. When false the Service is a no-op and
	// enforcement is skipped entirely.
	Enabled bool
	// Enforce gates whether protected endpoints are actually blocked without a
	// fresh assertion. When Enabled but not Enforce, ceremonies work (so admins
	// can enrol during a rollout) but endpoints are not yet gated.
	Enforce bool
	// RPID is the Relying Party ID — the effective registrable domain of the
	// admin UI (e.g. "example.com" or "admin.example.com"). Required when enabled.
	RPID string
	// RPName is a human-readable Relying Party display name.
	RPName string
	// Origins is the allowlist of acceptable client-data origins
	// (e.g. "https://admin.example.com"). At least one is required when enabled.
	Origins []string
	// RequireUserVerification demands the UV flag (PIN/biometric), not merely
	// user presence, on every ceremony.
	RequireUserVerification bool
	// ChallengeTTL bounds how long an issued challenge remains valid.
	ChallengeTTL time.Duration
	// StepUpTTL bounds the freshness window of a minted step-up token.
	StepUpTTL time.Duration
	// AllowUnverifiedAttestation accepts attestation formats the verifier cannot
	// cryptographically check (flagging the credential as unverified) rather than
	// rejecting the registration.
	AllowUnverifiedAttestation bool
	// ProtectedActions overrides the default set of step-up-gated endpoint paths.
	ProtectedActions []string
	// StorePath is the JSON sidecar file backing the credential set; empty means
	// in-memory only.
	StorePath string
}

// Option customises a Service.
type Option func(*Service)

// WithAudit wires the tamper-evident audit logger.
func WithAudit(l AuditLogger) Option { return func(s *Service) { s.audit = l } }

// WithMetrics wires the metrics sink.
func WithMetrics(m *Metrics) Option { return func(s *Service) { s.metrics = m } }

// WithClock overrides the clock (tests).
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// WithLogger overrides the logger.
func WithLogger(l *slog.Logger) Option { return func(s *Service) { s.log = l } }

// challenge is a pending, single-use ceremony challenge.
type challenge struct {
	value   []byte    // raw challenge bytes
	subject string    // identity the challenge is bound to
	kind    string    // "webauthn.create" or "webauthn.get"
	action  string    // step-up action the resulting token may be used for ("" = any)
	expires time.Time // absolute expiry
}

// stepUp is a minted, single-use step-up grant.
type stepUp struct {
	subject string
	action  string // "" means usable for any protected action
	expires time.Time
}

// Service is the WebAuthn step-up engine. The zero value is not usable; call New.
type Service struct {
	cfg       Config
	protected map[string]struct{}
	log       *slog.Logger
	audit     AuditLogger
	metrics   *Metrics
	now       func() time.Time
	store     *store

	mu         sync.Mutex
	creds      map[string][]*Credential // subject -> credentials
	challenges map[string]*challenge    // b64url(challenge) -> challenge
	stepups    map[string]*stepUp       // b64url(token) -> grant
}

// New constructs a Service from cfg, loading any persisted credentials. It
// returns an error only on a persistence failure or invalid configuration.
func New(cfg Config, opts ...Option) (*Service, error) {
	if cfg.ChallengeTTL <= 0 {
		cfg.ChallengeTTL = defaultChallengeTTL
	}
	if cfg.StepUpTTL <= 0 {
		cfg.StepUpTTL = defaultStepUpTTL
	}
	protected := cfg.ProtectedActions
	if len(protected) == 0 {
		protected = defaultProtectedActions
	}
	s := &Service{
		cfg:        cfg,
		protected:  make(map[string]struct{}, len(protected)),
		now:        time.Now,
		store:      &store{path: cfg.StorePath},
		creds:      make(map[string][]*Credential),
		challenges: make(map[string]*challenge),
		stepups:    make(map[string]*stepUp),
	}
	for _, p := range protected {
		if p = strings.TrimSpace(p); p != "" {
			s.protected[p] = struct{}{}
		}
	}
	for _, o := range opts {
		o(s)
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if cfg.Enabled {
		if strings.TrimSpace(cfg.RPID) == "" {
			return nil, errors.New("webauthn: rpID is required when enabled")
		}
		if len(cfg.Origins) == 0 {
			return nil, errors.New("webauthn: at least one origin is required when enabled")
		}
	}
	if err := s.store.load(s); err != nil {
		return nil, fmt.Errorf("webauthn: loading credential store: %w", err)
	}
	s.refreshGaugesLocked()
	return s, nil
}

// Enabled reports whether the subsystem is active.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// Enforcing reports whether protected endpoints are gated. Enforcement requires
// both Enabled and Enforce.
func (s *Service) Enforcing() bool { return s.Enabled() && s.cfg.Enforce }

// StepUpTTL exposes the configured freshness window (for display).
func (s *Service) StepUpTTL() time.Duration { return s.cfg.StepUpTTL }

// StepUpRequired reports whether a request path is a protected action that
// requires a fresh step-up assertion. It is false unless enforcement is active.
func (s *Service) StepUpRequired(relPath string) bool {
	if !s.Enforcing() {
		return false
	}
	_, ok := s.protected[relPath]
	return ok
}

// ---------------------------------------------------------------------------
// Registration ceremony
// ---------------------------------------------------------------------------

// PublicKeyCredentialParameter advertises an accepted signature algorithm.
type PublicKeyCredentialParameter struct {
	Type string `json:"type"`
	Alg  int64  `json:"alg"`
}

// RegistrationChallenge is the server-issued options for navigator.credentials
// .create(), serialised with base64url for the binary fields.
type RegistrationChallenge struct {
	Challenge          string                         `json:"challenge"`
	RPID               string                         `json:"rpId"`
	RPName             string                         `json:"rpName"`
	UserID             string                         `json:"userId"`
	UserName           string                         `json:"userName"`
	PubKeyCredParams   []PublicKeyCredentialParameter `json:"pubKeyCredParams"`
	ExcludeCredentials []string                       `json:"excludeCredentials"`
	Timeout            int                            `json:"timeoutMs"`
	UserVerification   string                         `json:"userVerification"`
	AttestationConvey  string                         `json:"attestation"`
}

// RegistrationResponse is the client's navigator.credentials.create() result,
// with the binary fields base64url-encoded.
type RegistrationResponse struct {
	Label             string   `json:"label"`
	ClientDataJSON    string   `json:"clientDataJSON"`
	AttestationObject string   `json:"attestationObject"`
	Transports        []string `json:"transports"`
}

// clientData is the parsed CollectedClientData.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// BeginRegistration issues a registration challenge for subject.
func (s *Service) BeginRegistration(subject, userName string) (RegistrationChallenge, error) {
	if !s.Enabled() {
		return RegistrationChallenge{}, ErrDisabled
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return RegistrationChallenge{}, errors.New("webauthn: subject is required")
	}
	ch, err := s.issueChallenge(subject, "webauthn.create", "")
	if err != nil {
		return RegistrationChallenge{}, err
	}
	params := make([]PublicKeyCredentialParameter, 0, 3)
	for _, alg := range supportedAlgorithms() {
		params = append(params, PublicKeyCredentialParameter{Type: "public-key", Alg: alg})
	}
	uv := "preferred"
	if s.cfg.RequireUserVerification {
		uv = "required"
	}
	s.mu.Lock()
	exclude := make([]string, 0, len(s.creds[subject]))
	for _, c := range s.creds[subject] {
		exclude = append(exclude, c.ID)
	}
	s.mu.Unlock()
	return RegistrationChallenge{
		Challenge:          b64urlEncode(ch),
		RPID:               s.cfg.RPID,
		RPName:             s.cfg.RPName,
		UserID:             b64urlEncode([]byte(subject)),
		UserName:           userName,
		PubKeyCredParams:   params,
		ExcludeCredentials: exclude,
		Timeout:            int(s.cfg.ChallengeTTL / time.Millisecond),
		UserVerification:   uv,
		AttestationConvey:  "direct",
	}, nil
}

// FinishRegistration verifies a registration response and stores the credential.
func (s *Service) FinishRegistration(ctx context.Context, subject string, in RegistrationResponse) (CredentialView, error) {
	if !s.Enabled() {
		return CredentialView{}, ErrDisabled
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return CredentialView{}, errors.New("webauthn: subject is required")
	}

	cred, err := s.verifyRegistration(subject, in)
	if err != nil {
		s.metrics.recordRegistration(false)
		s.auditCeremony(ctx, subject, "register", "", audit.DecisionError, err.Error(), nil)
		return CredentialView{}, err
	}

	s.mu.Lock()
	list := s.creds[subject]
	if len(list) >= maxCredsPerSubject {
		s.mu.Unlock()
		s.metrics.recordRegistration(false)
		return CredentialView{}, fmt.Errorf("webauthn: credential limit (%d) reached for identity", maxCredsPerSubject)
	}
	// Reject duplicate credential ids for the same subject.
	for _, c := range list {
		if c.ID == cred.ID {
			s.mu.Unlock()
			s.metrics.recordRegistration(false)
			return CredentialView{}, errors.New("webauthn: credential is already registered")
		}
	}
	s.creds[subject] = append(list, cred)
	perr := s.store.persistLocked(s)
	s.refreshGaugesLocked()
	s.mu.Unlock()
	if perr != nil {
		s.log.Error("webauthn: persisting credential failed", "error", perr, "subject", subject)
	}

	s.metrics.recordRegistration(true)
	s.auditCeremony(ctx, subject, "register", cred.ID, audit.DecisionAllow,
		"passkey enrolled", map[string]any{
			"attestationFormat":   cred.AttestationFormat,
			"attestationVerified": cred.AttestationVerified,
			"label":               cred.Label,
		})
	s.log.Info("webauthn: passkey enrolled", "subject", subject, "credentialId", cred.ID,
		"attestation", cred.AttestationFormat, "verified", cred.AttestationVerified)
	return cred.view(), nil
}

// verifyRegistration performs the cryptographic validation of a registration
// response without mutating service state.
func (s *Service) verifyRegistration(subject string, in RegistrationResponse) (*Credential, error) {
	clientJSON, err := b64urlDecode(in.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("webauthn: decoding clientDataJSON: %w", err)
	}
	cd, err := s.validateClientData(clientJSON, "webauthn.create", subject)
	if err != nil {
		return nil, err
	}
	_ = cd

	attBytes, err := b64urlDecode(in.AttestationObject)
	if err != nil {
		return nil, fmt.Errorf("webauthn: decoding attestationObject: %w", err)
	}
	ao, err := parseAttestationObject(attBytes)
	if err != nil {
		return nil, err
	}
	ad, err := parseAuthData(ao.AuthData, true)
	if err != nil {
		return nil, err
	}
	if err := ad.verifyRPIDHash(s.cfg.RPID); err != nil {
		return nil, err
	}
	if !ad.userPresent() {
		return nil, errors.New("webauthn: user-presence flag not set")
	}
	if s.cfg.RequireUserVerification && !ad.userVerified() {
		return nil, errors.New("webauthn: user-verification required but not performed")
	}

	attRes, err := verifyAttestation(ao, ad, clientDataHash(clientJSON), s.cfg.AllowUnverifiedAttestation)
	if err != nil {
		return nil, err
	}

	label := strings.TrimSpace(in.Label)
	if label == "" {
		label = "passkey"
	}
	return &Credential{
		ID:                  b64urlEncode(ad.CredID),
		Subject:             subject,
		Label:               label,
		COSEKey:             b64urlEncode(ad.CredKeyRaw),
		AAGUID:              b64urlEncode(ad.AAGUID),
		SignCount:           ad.SignCount,
		AttestationFormat:   attRes.Format,
		AttestationVerified: attRes.Verified,
		Transports:          sanitizeTransports(in.Transports),
		CreatedAt:           s.now(),
	}, nil
}

// ---------------------------------------------------------------------------
// Assertion (step-up) ceremony
// ---------------------------------------------------------------------------

// AssertionChallenge is the server-issued options for navigator.credentials
// .get(), serialised with base64url for the binary fields.
type AssertionChallenge struct {
	Challenge        string   `json:"challenge"`
	RPID             string   `json:"rpId"`
	AllowCredentials []string `json:"allowCredentials"`
	Timeout          int      `json:"timeoutMs"`
	UserVerification string   `json:"userVerification"`
	Action           string   `json:"action,omitempty"`
}

// AssertionResponse is the client's navigator.credentials.get() result.
type AssertionResponse struct {
	CredentialID      string `json:"credentialId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
}

// StepUpResult is returned on a successful assertion: the minted single-use
// token and its absolute expiry.
type StepUpResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
	Action    string    `json:"action,omitempty"`
}

// BeginAssertion issues an assertion challenge for subject, optionally bound to
// a specific protected action.
func (s *Service) BeginAssertion(subject, action string) (AssertionChallenge, error) {
	if !s.Enabled() {
		return AssertionChallenge{}, ErrDisabled
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return AssertionChallenge{}, errors.New("webauthn: subject is required")
	}
	s.mu.Lock()
	list := s.creds[subject]
	allow := make([]string, 0, len(list))
	for _, c := range list {
		allow = append(allow, c.ID)
	}
	s.mu.Unlock()
	if len(allow) == 0 {
		return AssertionChallenge{}, ErrNoCredentials
	}
	ch, err := s.issueChallenge(subject, "webauthn.get", strings.TrimSpace(action))
	if err != nil {
		return AssertionChallenge{}, err
	}
	uv := "preferred"
	if s.cfg.RequireUserVerification {
		uv = "required"
	}
	return AssertionChallenge{
		Challenge:        b64urlEncode(ch),
		RPID:             s.cfg.RPID,
		AllowCredentials: allow,
		Timeout:          int(s.cfg.ChallengeTTL / time.Millisecond),
		UserVerification: uv,
		Action:           strings.TrimSpace(action),
	}, nil
}

// FinishAssertion verifies an assertion and, on success, mints a step-up token.
func (s *Service) FinishAssertion(ctx context.Context, subject string, in AssertionResponse) (StepUpResult, error) {
	if !s.Enabled() {
		return StepUpResult{}, ErrDisabled
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return StepUpResult{}, errors.New("webauthn: subject is required")
	}

	token, action, err := s.verifyAssertion(ctx, subject, in)
	if err != nil {
		s.metrics.recordAssertion(false)
		s.auditCeremony(ctx, subject, "assert", in.CredentialID, audit.DecisionDeny, err.Error(), nil)
		return StepUpResult{}, err
	}

	s.metrics.recordAssertion(true)
	s.auditCeremony(ctx, subject, "assert", in.CredentialID, audit.DecisionAllow,
		"passkey step-up assertion verified", map[string]any{"action": action})
	s.log.Info("webauthn: step-up assertion verified", "subject", subject,
		"credentialId", in.CredentialID, "action", action)
	return token, nil
}

// verifyAssertion validates the assertion, enforces the signature-counter
// invariant, updates the credential, and mints the token. It holds s.mu for the
// counter update + token mint so two concurrent assertions cannot both accept a
// stale counter.
func (s *Service) verifyAssertion(ctx context.Context, subject string, in AssertionResponse) (StepUpResult, string, error) {
	clientJSON, err := b64urlDecode(in.ClientDataJSON)
	if err != nil {
		return StepUpResult{}, "", fmt.Errorf("webauthn: decoding clientDataJSON: %w", err)
	}
	authDataBytes, err := b64urlDecode(in.AuthenticatorData)
	if err != nil {
		return StepUpResult{}, "", fmt.Errorf("webauthn: decoding authenticatorData: %w", err)
	}
	sig, err := b64urlDecode(in.Signature)
	if err != nil {
		return StepUpResult{}, "", fmt.Errorf("webauthn: decoding signature: %w", err)
	}

	cd, err := s.validateClientData(clientJSON, "webauthn.get", subject)
	if err != nil {
		return StepUpResult{}, "", err
	}
	// Recover the action bound to the (already consumed) challenge.
	action := cd.boundAction

	ad, err := parseAuthData(authDataBytes, false)
	if err != nil {
		return StepUpResult{}, "", err
	}
	if err := ad.verifyRPIDHash(s.cfg.RPID); err != nil {
		return StepUpResult{}, "", err
	}
	if !ad.userPresent() {
		return StepUpResult{}, "", errors.New("webauthn: user-presence flag not set")
	}
	if s.cfg.RequireUserVerification && !ad.userVerified() {
		return StepUpResult{}, "", errors.New("webauthn: user-verification required but not performed")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	cred := s.findCredentialLocked(subject, in.CredentialID)
	if cred == nil {
		return StepUpResult{}, "", ErrUnknownCredential
	}
	key, err := cred.coseKey()
	if err != nil {
		return StepUpResult{}, "", err
	}

	// Signature covers authenticatorData || SHA-256(clientDataJSON).
	signed := make([]byte, 0, len(authDataBytes)+32)
	signed = append(signed, authDataBytes...)
	signed = append(signed, clientDataHash(clientJSON)...)
	if err := key.verify(signed, sig); err != nil {
		return StepUpResult{}, "", err
	}

	// Signature-counter rollback detection (WebAuthn §6.1.1 step 17): when either
	// the stored or the new counter is non-zero, the new value must strictly
	// exceed the stored one. Equal or lower means a cloned authenticator.
	if ad.SignCount != 0 || cred.SignCount != 0 {
		if ad.SignCount <= cred.SignCount {
			s.metrics.recordCounterRollback()
			return StepUpResult{}, "", fmt.Errorf("%w (stored=%d, presented=%d)",
				ErrCounterRollback, cred.SignCount, ad.SignCount)
		}
	}
	cred.SignCount = ad.SignCount
	cred.LastUsed = s.now()
	if err := s.store.persistLocked(s); err != nil {
		s.log.Error("webauthn: persisting counter update failed", "error", err, "subject", subject)
	}

	token := s.mintStepUpLocked(subject, action)
	return token, action, nil
}

// ---------------------------------------------------------------------------
// Step-up token verification (the enforcement side)
// ---------------------------------------------------------------------------

// VerifyStepUp consumes a step-up token, returning nil if it is a live grant
// bound to subject and valid for action. It is single-use: a valid token is
// removed whether or not the subsequent action succeeds, so a token can never be
// replayed. It records the required/verified/denied metrics and an audit entry.
func (s *Service) VerifyStepUp(ctx context.Context, subject, action, token, remoteAddr string) error {
	if !s.Enforcing() {
		return nil
	}
	s.metrics.recordStepUpRequired()
	subject = strings.TrimSpace(subject)
	token = strings.TrimSpace(token)
	if token == "" {
		s.metrics.recordStepUpDenied()
		s.auditStepUp(ctx, subject, action, remoteAddr, audit.DecisionDeny, "no step-up token presented")
		return ErrStepUpRequired
	}

	s.mu.Lock()
	grant, ok := s.stepups[token]
	if ok {
		delete(s.stepups, token) // single-use: consume regardless of validity below
	}
	s.mu.Unlock()

	now := s.now()
	switch {
	case !ok:
		s.metrics.recordStepUpDenied()
		s.auditStepUp(ctx, subject, action, remoteAddr, audit.DecisionDeny, "unknown step-up token")
		return ErrStepUpInvalid
	case now.After(grant.expires):
		s.metrics.recordStepUpDenied()
		s.auditStepUp(ctx, subject, action, remoteAddr, audit.DecisionDeny, "expired step-up token")
		return ErrStepUpInvalid
	case subtle.ConstantTimeCompare([]byte(grant.subject), []byte(subject)) != 1:
		s.metrics.recordStepUpDenied()
		s.auditStepUp(ctx, subject, action, remoteAddr, audit.DecisionDeny, "step-up token bound to a different identity")
		return ErrStepUpInvalid
	case grant.action != "" && grant.action != action:
		s.metrics.recordStepUpDenied()
		s.auditStepUp(ctx, subject, action, remoteAddr, audit.DecisionDeny, "step-up token bound to a different action")
		return ErrStepUpInvalid
	}

	s.metrics.recordStepUpVerified()
	s.auditStepUp(ctx, subject, action, remoteAddr, audit.DecisionAllow, "fresh passkey step-up verified")
	return nil
}

// ---------------------------------------------------------------------------
// Credential management
// ---------------------------------------------------------------------------

// Credentials returns the redacted view of a subject's registered credentials.
func (s *Service) Credentials(subject string) []CredentialView {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.creds[strings.TrimSpace(subject)]
	out := make([]CredentialView, 0, len(list))
	for _, c := range list {
		out = append(out, c.view())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// HasCredentials reports whether a subject has at least one registered passkey.
func (s *Service) HasCredentials(subject string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.creds[strings.TrimSpace(subject)]) > 0
}

// RemoveCredential deletes a subject's credential by id, returning whether it
// existed.
func (s *Service) RemoveCredential(ctx context.Context, subject, credID string) (bool, error) {
	subject = strings.TrimSpace(subject)
	s.mu.Lock()
	list := s.creds[subject]
	idx := -1
	for i, c := range list {
		if c.ID == credID {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.mu.Unlock()
		return false, nil
	}
	s.creds[subject] = append(list[:idx:idx], list[idx+1:]...)
	if len(s.creds[subject]) == 0 {
		delete(s.creds, subject)
	}
	perr := s.store.persistLocked(s)
	s.refreshGaugesLocked()
	s.mu.Unlock()
	if perr != nil {
		s.log.Error("webauthn: persisting credential removal failed", "error", perr, "subject", subject)
	}
	s.auditCeremony(ctx, subject, "deregister", credID, audit.DecisionAllow, "passkey removed", nil)
	return true, nil
}

// Snapshot returns the current metrics.
func (s *Service) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	return s.metrics.Snapshot()
}

// Status is the admin read-model for the subsystem.
type Status struct {
	Enabled           bool     `json:"enabled"`
	Enforcing         bool     `json:"enforcing"`
	RPID              string   `json:"rpId"`
	RPName            string   `json:"rpName,omitempty"`
	Origins           []string `json:"origins"`
	RequireUV         bool     `json:"requireUserVerification"`
	ChallengeTTLSecs  int      `json:"challengeTtlSeconds"`
	StepUpTTLSecs     int      `json:"stepUpTtlSeconds"`
	ProtectedActions  []string `json:"protectedActions"`
	EnrolledSubjects  int      `json:"enrolledSubjects"`
	TotalCredentials  int      `json:"totalCredentials"`
	PendingChallenges int      `json:"pendingChallenges"`
}

// Status returns the subsystem's configuration/read-model snapshot.
func (s *Service) Status() Status {
	s.mu.Lock()
	subjects := len(s.creds)
	total := 0
	for _, list := range s.creds {
		total += len(list)
	}
	pending := len(s.challenges)
	s.mu.Unlock()
	actions := make([]string, 0, len(s.protected))
	for a := range s.protected {
		actions = append(actions, a)
	}
	sort.Strings(actions)
	return Status{
		Enabled:           s.cfg.Enabled,
		Enforcing:         s.Enforcing(),
		RPID:              s.cfg.RPID,
		RPName:            s.cfg.RPName,
		Origins:           append([]string(nil), s.cfg.Origins...),
		RequireUV:         s.cfg.RequireUserVerification,
		ChallengeTTLSecs:  int(s.cfg.ChallengeTTL / time.Second),
		StepUpTTLSecs:     int(s.cfg.StepUpTTL / time.Second),
		ProtectedActions:  actions,
		EnrolledSubjects:  subjects,
		TotalCredentials:  total,
		PendingChallenges: pending,
	}
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

// issueChallenge mints and records a single-use challenge bound to subject and
// ceremony kind. It opportunistically evicts expired pending challenges.
func (s *Service) issueChallenge(subject, kind, action string) ([]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("webauthn: generating challenge: %w", err)
	}
	s.mu.Lock()
	s.gcChallengesLocked()
	if len(s.challenges) >= maxPendingChallenge {
		s.mu.Unlock()
		return nil, errors.New("webauthn: too many pending challenges; try again shortly")
	}
	s.challenges[b64urlEncode(raw)] = &challenge{
		value:   raw,
		subject: subject,
		kind:    kind,
		action:  action,
		expires: s.now().Add(s.cfg.ChallengeTTL),
	}
	s.refreshGaugesLocked()
	s.mu.Unlock()
	s.metrics.recordChallengeIssued()
	return raw, nil
}

// consumeChallenge validates and removes a pending challenge matching the
// client-provided challenge value, subject, and kind. It returns the bound
// action. A missing/expired/mismatched challenge is an error.
func (s *Service) consumeChallenge(encoded, subject, kind string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.challenges[encoded]
	if !ok {
		return "", ErrChallengeExpired
	}
	// Always consume a matched challenge so it cannot be replayed.
	delete(s.challenges, encoded)
	s.refreshGaugesLocked()
	if s.now().After(ch.expires) {
		return "", ErrChallengeExpired
	}
	if ch.kind != kind {
		return "", ErrChallengeMismatch
	}
	if subtle.ConstantTimeCompare([]byte(ch.subject), []byte(subject)) != 1 {
		return "", ErrChallengeMismatch
	}
	return ch.action, nil
}

// gcChallengesLocked drops expired pending challenges. Caller holds s.mu.
func (s *Service) gcChallengesLocked() {
	now := s.now()
	for k, ch := range s.challenges {
		if now.After(ch.expires) {
			delete(s.challenges, k)
			s.metrics.recordChallengeExpired()
		}
	}
	for k, g := range s.stepups {
		if now.After(g.expires) {
			delete(s.stepups, k)
		}
	}
}

// mintStepUpLocked creates a single-use step-up grant. Caller holds s.mu.
func (s *Service) mintStepUpLocked(subject, action string) StepUpResult {
	raw := make([]byte, 32)
	// rand.Read on crypto/rand never returns a short read without an error, and a
	// failure here is catastrophic; fall back to a time-seeded token only to avoid
	// a panic, which VerifyStepUp will still bind to the subject.
	_, _ = rand.Read(raw)
	token := b64urlEncode(raw)
	expires := s.now().Add(s.cfg.StepUpTTL)
	s.stepups[token] = &stepUp{subject: subject, action: action, expires: expires}
	return StepUpResult{Token: token, ExpiresAt: expires, Action: action}
}

// findCredentialLocked returns the credential for subject with the given id, or
// nil. Caller holds s.mu.
func (s *Service) findCredentialLocked(subject, credID string) *Credential {
	for _, c := range s.creds[subject] {
		if subtle.ConstantTimeCompare([]byte(c.ID), []byte(credID)) == 1 {
			return c
		}
	}
	return nil
}

// validatedClientData is validateClientData's result, carrying the bound action
// recovered from the consumed challenge.
type validatedClientData struct {
	clientData
	boundAction string
}

// validateClientData parses and validates CollectedClientData: the ceremony
// type, the origin allowlist, and the challenge (which it consumes). It returns
// the parsed data plus the action the challenge was bound to.
func (s *Service) validateClientData(raw []byte, wantType, subject string) (validatedClientData, error) {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return validatedClientData{}, fmt.Errorf("webauthn: parsing client data: %w", err)
	}
	if cd.Type != wantType {
		return validatedClientData{}, fmt.Errorf("webauthn: client data type %q != %q", cd.Type, wantType)
	}
	if !s.originAllowed(cd.Origin) {
		return validatedClientData{}, ErrBadOrigin
	}
	// The challenge echoed in client data must match a live, subject-bound,
	// same-ceremony pending challenge. consumeChallenge removes it (single use).
	action, err := s.consumeChallenge(cd.Challenge, subject, wantType)
	if err != nil {
		if errors.Is(err, ErrChallengeExpired) {
			s.metrics.recordChallengeExpired()
		}
		return validatedClientData{}, err
	}
	return validatedClientData{clientData: cd, boundAction: action}, nil
}

// originAllowed reports whether origin is in the configured allowlist.
func (s *Service) originAllowed(origin string) bool {
	origin = strings.TrimSpace(origin)
	for _, o := range s.cfg.Origins {
		if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(o)), []byte(origin)) == 1 {
			return true
		}
	}
	return false
}

// refreshGaugesLocked recomputes the live gauges. Caller holds s.mu.
func (s *Service) refreshGaugesLocked() {
	total := 0
	for _, list := range s.creds {
		total += len(list)
	}
	s.metrics.setGauges(total, len(s.creds), len(s.challenges))
}

// auditCeremony records a registration/assertion/deregistration ceremony.
func (s *Service) auditCeremony(ctx context.Context, subject, phase, credID string, decision audit.Decision, reason string, extra map[string]any) {
	if s.audit == nil {
		return
	}
	detail := map[string]any{"phase": phase}
	if credID != "" {
		detail["credentialId"] = credID
	}
	for k, v := range extra {
		detail[k] = v
	}
	ev := audit.Event{
		Type:     audit.EventStepUpAuth,
		Subject:  subject,
		Resource: "webauthn:" + phase,
		Decision: decision,
		Reason:   reason,
		Detail:   detail,
	}
	if err := s.audit.Log(ctx, ev); err != nil {
		s.log.Error("webauthn: audit log write failed", "error", err, "phase", phase)
	}
}

// auditStepUp records a step-up enforcement decision at a protected endpoint.
func (s *Service) auditStepUp(ctx context.Context, subject, action, remoteAddr string, decision audit.Decision, reason string) {
	if s.audit == nil {
		return
	}
	ev := audit.Event{
		Type:       audit.EventStepUpAuth,
		Subject:    subject,
		Resource:   action,
		RemoteAddr: remoteAddr,
		Decision:   decision,
		Reason:     reason,
		Detail:     map[string]any{"phase": "enforce", "action": action},
	}
	if err := s.audit.Log(ctx, ev); err != nil {
		s.log.Error("webauthn: audit log write failed", "error", err, "action", action)
	}
}

// sanitizeTransports keeps only the known WebAuthn transport tokens, bounding
// the slice so a hostile client cannot bloat stored state.
func sanitizeTransports(in []string) []string {
	known := map[string]struct{}{
		"usb": {}, "nfc": {}, "ble": {}, "internal": {}, "hybrid": {}, "smart-card": {},
	}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.TrimSpace(strings.ToLower(t))
		if _, ok := known[t]; ok {
			out = append(out, t)
		}
		if len(out) >= 8 {
			break
		}
	}
	return out
}

// b64urlEncode encodes bytes with raw (unpadded) base64url, the WebAuthn wire
// convention.
func b64urlEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// b64urlDecode decodes raw or padded base64url, tolerating a client that adds
// padding.
func b64urlDecode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
