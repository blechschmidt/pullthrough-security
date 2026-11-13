package watch

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// maxWebhookBody bounds the push payload we read, so a hostile or runaway
// delivery cannot exhaust memory. GitHub caps push payloads at 25 MiB; we allow
// a generous but finite ceiling.
const maxWebhookBody = 25 << 20

// MaxWebhookBody is the largest push payload a receiver built on this package
// reads (the repository tracker of Task 180 shares the limit).
const MaxWebhookBody = maxWebhookBody

// pushPayload is the subset of a GitHub (and GitHub-compatible, e.g. Gitea)
// push-event payload the watcher consumes.
type pushPayload struct {
	Ref        string `json:"ref"`
	Before     string `json:"before"`
	After      string `json:"after"`
	Created    bool   `json:"created"`
	Deleted    bool   `json:"deleted"`
	Repository struct {
		FullName string `json:"full_name"`
		CloneURL string `json:"clone_url"`
		SSHURL   string `json:"ssh_url"`
		HTMLURL  string `json:"html_url"`
		GitURL   string `json:"git_url"`
	} `json:"repository"`
}

// PushEvent is a push webhook delivery, as the repository tracker (Task 180)
// consumes it: which ref moved from where to where, and which repository it
// belongs to. It is the exported form of the payload the commit watcher reads.
type PushEvent struct {
	// Ref is the fully-qualified ref ("refs/tags/v1.2.0", "refs/heads/main").
	Ref string `json:"ref"`
	// Before and After are the ref's old and new object IDs; all zeros for a
	// created (Before) or deleted (After) ref.
	Before string `json:"before"`
	After  string `json:"after"`
	// Created and Deleted report a ref that appeared or disappeared.
	Created bool `json:"created"`
	Deleted bool `json:"deleted"`
	// FullName ("owner/repo") and URLs identify the repository.
	FullName string   `json:"fullName,omitempty"`
	URLs     []string `json:"urls,omitempty"`
}

// ParsePush reads a push payload. Callers verify the signature first
// (VerifySignature): an unauthenticated payload must not be interpreted.
func ParsePush(body []byte) (PushEvent, error) {
	var p pushPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return PushEvent{}, err
	}
	ev := PushEvent{
		Ref:      p.Ref,
		Before:   p.Before,
		After:    p.After,
		Created:  p.Created,
		Deleted:  p.Deleted || (p.After != "" && isZeroSHA(p.After)),
		FullName: p.Repository.FullName,
	}
	for _, u := range []string{p.Repository.CloneURL, p.Repository.SSHURL, p.Repository.GitURL, p.Repository.HTMLURL} {
		if strings.TrimSpace(u) != "" {
			ev.URLs = append(ev.URLs, u)
		}
	}
	return ev, nil
}

// Names reports whether the push is for the repository at url, or named
// fullName ("owner/repo"), the way the commit watcher routes deliveries.
func (e PushEvent) Names(url, fullName string) bool {
	if fullName != "" && strings.EqualFold(fullName, e.FullName) {
		return true
	}
	for _, u := range e.URLs {
		if urlMatches(url, u) {
			return true
		}
	}
	return false
}

// WebhookEvent returns the delivery's event type from the GitHub
// (X-GitHub-Event) or Gitea (X-Gitea-Event) header; "" when neither is set.
func WebhookEvent(h http.Header) string {
	event := h.Get("X-GitHub-Event")
	if event == "" {
		event = h.Get("X-Gitea-Event")
	}
	return event
}

// VerifySignature validates the GitHub-style HMAC-SHA256 signature
// ("X-Hub-Signature-256: sha256=<hex>") of body under secret, in constant time.
// An empty secret disables verification and accepts any body.
func VerifySignature(secret string, h http.Header, body []byte) bool {
	if secret == "" {
		return true
	}
	sig := h.Get("X-Hub-Signature-256")
	const prefix = "sha256="
	if !strings.HasPrefix(sig, prefix) {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(sig, prefix))
	if err != nil {
		return false
	}
	return hmac.Equal(got, computeSignature(secret, body))
}

// WebhookHandler returns an http.Handler for the push-webhook receiver. ctx is
// the server lifetime context used for the asynchronous scan that a delivery
// triggers (detached from the short-lived request so a slow LLM scan does not
// block the webhook response, which the sender times out quickly).
//
// POST with a valid signature and a push payload for a watched repository
// returns 202 Accepted and schedules an incremental scan. GET returns the
// watcher status as JSON. A GitHub "ping" event returns 200. A bad signature
// returns 401; an unknown repository returns 404 (unless unconfigured webhooks
// are allowed); a malformed payload returns 400.
func (s *Service) WebhookHandler(ctx context.Context) http.Handler {
	if ctx == nil {
		ctx = context.Background()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.writeJSON(w, http.StatusOK, s.Snapshot())
			return
		case http.MethodPost:
			s.handleWebhookPost(ctx, w, r)
			return
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func (s *Service) handleWebhookPost(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody))
	if err != nil {
		s.incWebhook(true)
		s.metrics.ObserveWebhook(true)
		http.Error(w, "reading request body", http.StatusBadRequest)
		return
	}

	// Verify the HMAC signature over the raw body before parsing anything, so an
	// unauthenticated payload is never interpreted.
	if !s.verifySignature(r.Header, body) {
		s.incWebhook(true)
		s.metrics.ObserveWebhook(true)
		s.logger.Warn("commit-watch webhook rejected: invalid or missing signature",
			"remote", r.RemoteAddr)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// GitHub sends a "ping" on hook creation; acknowledge it so the setup check
	// in the GitHub UI succeeds.
	event := WebhookEvent(r.Header)
	if event == "ping" {
		s.incWebhook(false)
		s.metrics.ObserveWebhook(false)
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "pong"})
		return
	}
	if event != "" && event != "push" {
		// Non-push events are accepted but ignored (we only scan on pushes).
		s.incWebhook(false)
		s.metrics.ObserveWebhook(false)
		s.writeJSON(w, http.StatusAccepted, map[string]string{"status": "ignored", "event": event})
		return
	}

	var payload pushPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		s.incWebhook(true)
		s.metrics.ObserveWebhook(true)
		http.Error(w, "malformed push payload", http.StatusBadRequest)
		return
	}

	repo, ok := s.routeRepo(payload)
	if !ok {
		s.incWebhook(true)
		s.metrics.ObserveWebhook(true)
		s.logger.Warn("commit-watch webhook for unwatched repository ignored",
			"fullName", payload.Repository.FullName, "cloneUrl", payload.Repository.CloneURL)
		http.Error(w, "repository not watched", http.StatusNotFound)
		return
	}

	// A branch deletion carries no new commits to scan.
	if payload.Deleted || isZeroSHA(payload.After) {
		s.incWebhook(false)
		s.metrics.ObserveWebhook(false)
		s.writeJSON(w, http.StatusAccepted, map[string]any{"status": "ignored", "reason": "ref deleted", "repo": repo.Name})
		return
	}

	hint := &UpdateHint{Refs: []RefUpdate{{
		Ref:    payload.Ref,
		Before: payload.Before,
		After:  payload.After,
	}}}

	s.incWebhook(false)
	s.metrics.ObserveWebhook(false)
	s.logger.Info("commit-watch webhook accepted",
		"repo", repo.Name, "ref", payload.Ref, "after", shortSHA(payload.After))

	if s.webhookSync {
		res, err := s.processRepo(ctx, repo, hint, false)
		if err != nil {
			s.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.writeJSON(w, http.StatusOK, res)
		return
	}

	// Schedule the scan detached from the request so the sender gets a prompt
	// acknowledgement; track it on the wait group so Close drains in-flight scans.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if _, err := s.processRepo(ctx, repo, hint, false); err != nil {
			s.logger.Error("commit-watch webhook scan failed", "repo", repo.Name, "error", err)
			s.incErrors()
		}
	}()
	s.writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "repo": repo.Name, "ref": payload.Ref})
}

// verifySignature validates the GitHub-style HMAC-SHA256 signature of body
// against the configured secret. When no secret is configured it returns true
// (verification disabled). The header is "X-Hub-Signature-256: sha256=<hex>".
func (s *Service) verifySignature(h http.Header, body []byte) bool {
	// An empty secret disables verification (trusted-network deployment); the
	// comparison is constant-time so the expected signature does not leak.
	return VerifySignature(s.cfg.WebhookSecret, h, body)
}

// computeSignature returns the raw HMAC-SHA256 of body keyed by secret.
func computeSignature(secret string, body []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return mac.Sum(nil)
}

// SignBody returns the full "sha256=<hex>" header value for body under secret.
// It is exported so callers (and tests) can produce a matching signature.
func SignBody(secret string, body []byte) string {
	return "sha256=" + hex.EncodeToString(computeSignature(secret, body))
}

// routeRepo maps a push payload to a configured watched repository, matching on
// full name then on any of the payload's clone URLs. When no match is found and
// AllowUnconfiguredWebhooks is set, an ad-hoc RepoRef is synthesized from the
// payload so the push can still be scanned.
func (s *Service) routeRepo(p pushPayload) (RepoRef, bool) {
	for _, r := range s.cfg.Repos {
		if r.FullName != "" && strings.EqualFold(r.FullName, p.Repository.FullName) {
			return r, true
		}
		if urlMatches(r.URL, p.Repository.CloneURL) ||
			urlMatches(r.URL, p.Repository.SSHURL) ||
			urlMatches(r.URL, p.Repository.GitURL) ||
			urlMatches(r.URL, p.Repository.HTMLURL) {
			return r, true
		}
	}
	if s.cfg.AllowUnconfiguredWebhooks {
		url := p.Repository.CloneURL
		if url == "" {
			url = p.Repository.HTMLURL
		}
		name := p.Repository.FullName
		if name == "" {
			name = deriveName(url)
		}
		if url != "" && name != "" {
			return RepoRef{Name: name, URL: url, FullName: p.Repository.FullName}, true
		}
	}
	return RepoRef{}, false
}

// urlMatches compares two clone URLs ignoring a trailing ".git" and case in the
// host, so "https://github.com/o/r" and "https://github.com/o/r.git" match.
func urlMatches(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return normalizeCloneURL(a) == normalizeCloneURL(b)
}

func normalizeCloneURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimSuffix(u, "/")
	u = strings.TrimSuffix(u, ".git")
	return strings.ToLower(u)
}

// deriveName extracts an "owner/repo"-style name from a clone URL for ad-hoc
// webhook repos.
func deriveName(u string) string {
	n := normalizeCloneURL(u)
	if i := strings.Index(n, "://"); i >= 0 {
		n = n[i+3:]
	}
	if i := strings.IndexByte(n, '/'); i >= 0 {
		n = n[i+1:]
	}
	return strings.ReplaceAll(n, "/", "-")
}

func (s *Service) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func isZeroSHA(sha string) bool {
	sha = strings.TrimSpace(sha)
	if sha == "" {
		return true
	}
	for _, c := range sha {
		if c != '0' {
			return false
		}
	}
	return true
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
