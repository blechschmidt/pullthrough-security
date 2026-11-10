package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeVault is a minimal in-memory Vault stand-in supporting approle login,
// token renew-self, and KV v2 reads.
type fakeVault struct {
	mu        sync.Mutex
	secret    string // current value of kv/data/app#password
	logins    int32
	renews    int32
	lastToken string
}

func (f *fakeVault) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.logins, 1)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["role_id"] != "role-123" || body["secret_id"] != "secret-456" {
			http.Error(w, `{"errors":["bad approle"]}`, http.StatusForbidden)
			return
		}
		writeJSON(w, map[string]any{
			"auth": map[string]any{"client_token": "tok-login", "lease_duration": 30, "renewable": true},
		})
	})
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.renews, 1)
		f.mu.Lock()
		f.lastToken = r.Header.Get("X-Vault-Token")
		f.mu.Unlock()
		writeJSON(w, map[string]any{
			"auth": map[string]any{"client_token": "", "lease_duration": 30, "renewable": true},
		})
	})
	mux.HandleFunc("/v1/secret/data/app", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			http.Error(w, `{"errors":["missing token"]}`, http.StatusForbidden)
			return
		}
		f.mu.Lock()
		val := f.secret
		f.mu.Unlock()
		writeJSON(w, map[string]any{
			"data": map[string]any{"data": map[string]any{"password": val, "note": 42}},
		})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestVaultProviderAppRoleAndKVRead(t *testing.T) {
	fv := &fakeVault{secret: "initial-pw"}
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	m := NewMetrics()
	p, err := NewVaultProvider(VaultOptions{
		Address:         srv.URL,
		AuthMethod:      "approle",
		RoleID:          "role-123",
		SecretID:        "secret-456",
		RefreshInterval: time.Hour, // keep the loop out of the way
	}, m, nil)
	if err != nil {
		t.Fatalf("new vault provider: %v", err)
	}
	defer p.Close()

	if atomic.LoadInt32(&fv.logins) != 1 {
		t.Fatalf("expected one approle login, got %d", fv.logins)
	}

	ref, _ := ParseRef("vault://app#password")
	got, err := p.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "initial-pw" {
		t.Fatalf("got %q", got)
	}

	// A missing key is a precise error that never dumps the secret body.
	badRef, _ := ParseRef("vault://app#nonexistent")
	if _, err := p.Resolve(context.Background(), badRef); err == nil {
		t.Fatalf("expected error for missing key")
	}
}

func TestVaultProviderRefreshDetectsRotation(t *testing.T) {
	fv := &fakeVault{secret: "v1"}
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	m := NewMetrics()
	p, err := NewVaultProvider(VaultOptions{
		Address:         srv.URL,
		AuthMethod:      "token",
		Token:           "static-token",
		RefreshInterval: time.Hour,
	}, m, nil)
	if err != nil {
		t.Fatalf("new vault provider: %v", err)
	}
	defer p.Close()

	var rotated []string
	var rmu sync.Mutex
	p.SetOnChange(func(ref string) {
		rmu.Lock()
		rotated = append(rotated, ref)
		rmu.Unlock()
	})

	ref, _ := ParseRef("vault://app#password")
	if v, err := p.Resolve(context.Background(), ref); err != nil || v != "v1" {
		t.Fatalf("resolve v1: %q %v", v, err)
	}

	// Rotate the backing secret and drive a manual refresh cycle.
	fv.mu.Lock()
	fv.secret = "v2"
	fv.mu.Unlock()
	p.refreshOnce()

	rmu.Lock()
	n := len(rotated)
	rmu.Unlock()
	if n != 1 || rotated[0] != "vault://app#password" {
		t.Fatalf("expected one rotation callback, got %v", rotated)
	}
	snap := m.Snapshot()
	if snap.Rotations != 1 {
		t.Fatalf("expected rotations=1, got %d", snap.Rotations)
	}
	if snap.RefreshSuccess < 1 {
		t.Fatalf("expected a successful refresh, got %+v", snap)
	}

	// A second refresh with no change fires no callback.
	p.refreshOnce()
	rmu.Lock()
	n = len(rotated)
	rmu.Unlock()
	if n != 1 {
		t.Fatalf("stable secret must not fire onChange again, got %d", n)
	}
}

func TestVaultProviderTokenRenewal(t *testing.T) {
	fv := &fakeVault{secret: "pw"}
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	p, err := NewVaultProvider(VaultOptions{
		Address:         srv.URL,
		AuthMethod:      "approle",
		RoleID:          "role-123",
		SecretID:        "secret-456",
		RefreshInterval: time.Hour,
	}, NewMetrics(), nil)
	if err != nil {
		t.Fatalf("new vault provider: %v", err)
	}
	defer p.Close()

	// The login lease is 30s and renewable; a manual refresh within one interval
	// of expiry must renew.
	p.refreshOnce()
	if atomic.LoadInt32(&fv.renews) == 0 {
		t.Fatalf("expected a token renewal")
	}
}
