package watch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

func pushBody(t *testing.T, ref, before, after, fullName, cloneURL string) []byte {
	t.Helper()
	p := map[string]any{
		"ref":    ref,
		"before": before,
		"after":  after,
		"repository": map[string]any{
			"full_name": fullName,
			"clone_url": cloneURL,
		},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newWebhookService(t *testing.T, secret string, repos []RepoRef, allowUnconfigured bool) (*Service, *fakeScanner, *fakeSource) {
	t.Helper()
	sc := newFakeScanner("sig1")
	src := newFakeSource()
	svc := newTestService(t, Config{
		Repos:                     repos,
		WebhookSecret:             secret,
		AllowUnconfiguredWebhooks: allowUnconfigured,
		Backfill:                  true,
	}, sc, src, nil)
	svc.SetWebhookSync(true)
	return svc, sc, src
}

func TestWebhookValidSignatureScans(t *testing.T) {
	secret := "s3cr3t"
	repo := RepoRef{Name: "r1", URL: "https://github.com/acme/r1.git", FullName: "acme/r1"}
	svc, sc, src := newWebhookService(t, secret, []RepoRef{repo}, false)
	src.queue("r1", &Batch{Commits: []*commit.Commit{mkCommit("deadbeef")}, Tips: map[string]string{"refs/heads/main": "deadbeef"}})

	body := pushBody(t, "refs/heads/main", "0000000000000000000000000000000000000000", "deadbeef", "acme/r1", "https://github.com/acme/r1.git")
	req := httptest.NewRequest(http.MethodPost, "/webhooks/git", strings.NewReader(string(body)))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-Hub-Signature-256", SignBody(secret, body))

	rec := httptest.NewRecorder()
	svc.WebhookHandler(context.Background()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := sc.scannedList(); len(got) != 1 || got[0] != "deadbeef" {
		t.Fatalf("scanned = %v, want [deadbeef]", got)
	}
	// The hint carried the pushed ref.
	if h := src.lastHint["r1"]; h == nil || len(h.Refs) != 1 || h.Refs[0].After != "deadbeef" {
		t.Fatalf("hint not propagated: %+v", src.lastHint["r1"])
	}
}

func TestWebhookInvalidSignatureRejected(t *testing.T) {
	secret := "s3cr3t"
	repo := RepoRef{Name: "r1", URL: "https://github.com/acme/r1.git", FullName: "acme/r1"}
	svc, sc, _ := newWebhookService(t, secret, []RepoRef{repo}, false)

	body := pushBody(t, "refs/heads/main", "x", "deadbeef", "acme/r1", "https://github.com/acme/r1.git")
	req := httptest.NewRequest(http.MethodPost, "/webhooks/git", strings.NewReader(string(body)))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")

	rec := httptest.NewRecorder()
	svc.WebhookHandler(context.Background()).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if len(sc.scannedList()) != 0 {
		t.Fatalf("scanned despite bad signature")
	}
	if svc.Snapshot().WebhooksRejected != 1 {
		t.Fatalf("rejected counter = %d, want 1", svc.Snapshot().WebhooksRejected)
	}
}

func TestWebhookMissingSignatureRejectedWhenSecretSet(t *testing.T) {
	repo := RepoRef{Name: "r1", URL: "u", FullName: "acme/r1"}
	svc, _, _ := newWebhookService(t, "secret", []RepoRef{repo}, false)
	body := pushBody(t, "refs/heads/main", "0", "abc", "acme/r1", "u")
	req := httptest.NewRequest(http.MethodPost, "/w", strings.NewReader(string(body)))
	req.Header.Set("X-GitHub-Event", "push")
	rec := httptest.NewRecorder()
	svc.WebhookHandler(context.Background()).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestWebhookNoSecretAcceptsUnsigned(t *testing.T) {
	repo := RepoRef{Name: "r1", URL: "https://github.com/acme/r1.git", FullName: "acme/r1"}
	svc, sc, src := newWebhookService(t, "", []RepoRef{repo}, false)
	src.queue("r1", &Batch{Commits: []*commit.Commit{mkCommit("abc")}, Tips: map[string]string{"refs/heads/main": "abc"}})
	body := pushBody(t, "refs/heads/main", "0", "abc", "acme/r1", "https://github.com/acme/r1.git")
	req := httptest.NewRequest(http.MethodPost, "/w", strings.NewReader(string(body)))
	req.Header.Set("X-GitHub-Event", "push")
	rec := httptest.NewRecorder()
	svc.WebhookHandler(context.Background()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if len(sc.scannedList()) != 1 {
		t.Fatalf("expected scan with no secret configured")
	}
}

func TestWebhookUnknownRepo404(t *testing.T) {
	repo := RepoRef{Name: "r1", URL: "https://github.com/acme/r1.git", FullName: "acme/r1"}
	svc, _, _ := newWebhookService(t, "", []RepoRef{repo}, false)
	body := pushBody(t, "refs/heads/main", "0", "abc", "other/repo", "https://github.com/other/repo.git")
	req := httptest.NewRequest(http.MethodPost, "/w", strings.NewReader(string(body)))
	req.Header.Set("X-GitHub-Event", "push")
	rec := httptest.NewRecorder()
	svc.WebhookHandler(context.Background()).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestWebhookPing(t *testing.T) {
	svc, _, _ := newWebhookService(t, "", nil, false)
	req := httptest.NewRequest(http.MethodPost, "/w", strings.NewReader("{}"))
	req.Header.Set("X-GitHub-Event", "ping")
	rec := httptest.NewRecorder()
	svc.WebhookHandler(context.Background()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ping status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "pong") {
		t.Fatalf("ping body = %q, want pong", rec.Body.String())
	}
}

func TestWebhookBranchDeletionIgnored(t *testing.T) {
	repo := RepoRef{Name: "r1", URL: "https://github.com/acme/r1.git", FullName: "acme/r1"}
	svc, sc, _ := newWebhookService(t, "", []RepoRef{repo}, false)
	body := pushBody(t, "refs/heads/feature", "abc", "0000000000000000000000000000000000000000", "acme/r1", "https://github.com/acme/r1.git")
	req := httptest.NewRequest(http.MethodPost, "/w", strings.NewReader(string(body)))
	req.Header.Set("X-GitHub-Event", "push")
	rec := httptest.NewRecorder()
	svc.WebhookHandler(context.Background()).ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (ignored deletion)", rec.Code)
	}
	if len(sc.scannedList()) != 0 {
		t.Fatalf("scanned on branch deletion")
	}
}

func TestWebhookUnconfiguredAllowed(t *testing.T) {
	svc, sc, src := newWebhookService(t, "", nil, true)
	src.queue("acme/r1", &Batch{Commits: []*commit.Commit{mkCommit("abc")}, Tips: map[string]string{"refs/heads/main": "abc"}})
	body := pushBody(t, "refs/heads/main", "0", "abc", "acme/r1", "https://github.com/acme/r1.git")
	req := httptest.NewRequest(http.MethodPost, "/w", strings.NewReader(string(body)))
	req.Header.Set("X-GitHub-Event", "push")
	rec := httptest.NewRecorder()
	svc.WebhookHandler(context.Background()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if len(sc.scannedList()) != 1 {
		t.Fatalf("expected ad-hoc scan for unconfigured repo")
	}
}

func TestWebhookGETStatus(t *testing.T) {
	svc, _, _ := newWebhookService(t, "", []RepoRef{{Name: "r1", URL: "u"}}, false)
	req := httptest.NewRequest(http.MethodGet, "/w", nil)
	rec := httptest.NewRecorder()
	svc.WebhookHandler(context.Background()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", rec.Code)
	}
	var st Stats
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decoding status: %v", err)
	}
	if st.ReposWatched != 1 {
		t.Fatalf("reposWatched = %d, want 1", st.ReposWatched)
	}
}

func TestVerifySignatureConstantTimeAndFormat(t *testing.T) {
	svc := &Service{cfg: Config{WebhookSecret: "k"}}
	body := []byte("hello")
	h := http.Header{}
	h.Set("X-Hub-Signature-256", SignBody("k", body))
	if !svc.verifySignature(h, body) {
		t.Fatalf("valid signature rejected")
	}
	h.Set("X-Hub-Signature-256", "sha1=abcd") // wrong algo prefix
	if svc.verifySignature(h, body) {
		t.Fatalf("accepted wrong-prefix signature")
	}
	h.Set("X-Hub-Signature-256", SignBody("different-key", body))
	if svc.verifySignature(h, body) {
		t.Fatalf("accepted signature from wrong key")
	}
}
