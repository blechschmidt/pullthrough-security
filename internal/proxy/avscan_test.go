package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/avscan"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/huggingface"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// avTestEngine is an injectable avscan.Engine that reports infected when the
// scanned payload contains a marker string.
type avTestEngine struct {
	marker    string
	signature string
	err       error
}

func (e *avTestEngine) Name() string { return "test-av" }
func (e *avTestEngine) Scan(ctx context.Context, r io.Reader) (avscan.Verdict, error) {
	data, _ := io.ReadAll(r)
	if e.err != nil {
		return avscan.Verdict{}, e.err
	}
	if e.marker != "" && strings.Contains(string(data), e.marker) {
		return avscan.Verdict{Infected: true, Signature: e.signature, Bytes: int64(len(data))}, nil
	}
	return avscan.Verdict{Bytes: int64(len(data))}, nil
}
func (e *avTestEngine) Ping(ctx context.Context) error { return e.err }

func newAVScanGateway(t *testing.T, upstreamURL string, svc *avscan.Service) *Gateway {
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
		AVScan:     svc,
		Ecosystems: map[string]string{"huggingface": "huggingface"},
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func mustAVScan(t *testing.T, action avscan.Action, failOpen bool, eng avscan.Engine) *avscan.Service {
	t.Helper()
	svc, err := avscan.NewService(avscan.Config{
		Enabled: true, Action: action, FailOpen: failOpen, EngineImpl: eng,
	})
	if err != nil {
		t.Fatalf("avscan.NewService: %v", err)
	}
	return svc
}

func TestAVScanGateQuarantinesInfectedArtifact(t *testing.T) {
	eng := &avTestEngine{marker: "INFECT-ME", signature: "Test.Malware"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("harmless prefix ... INFECT-ME ... suffix"))
	}))
	defer srv.Close()

	g := newAVScanGateway(t, srv.URL, mustAVScan(t, avscan.ActionQuarantine, true, eng))

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/huggingface/evil/model/resolve/main/pytorch_model.bin", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-AVScan-Decision") != "block" {
		t.Errorf("X-AVScan-Decision = %q, want block", rr.Header().Get("X-AVScan-Decision"))
	}
	var body avScanError
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Code != "infected" || body.Signature != "Test.Malware" {
		t.Errorf("unexpected block body: %+v", body)
	}

	// Quarantine must have evicted the artifact: a re-pull re-fetches and is
	// blocked again rather than served from cache.
	rr2 := httptest.NewRecorder()
	g.routes().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/v1/huggingface/evil/model/resolve/main/pytorch_model.bin", nil))
	if rr2.Code != http.StatusForbidden {
		t.Errorf("re-pull status = %d, want 403 (infected artifact must not be served from cache)", rr2.Code)
	}
}

func TestAVScanGateServesCleanArtifact(t *testing.T) {
	eng := &avTestEngine{marker: "INFECT-ME", signature: "Test.Malware"}
	payload := []byte("perfectly clean model weights")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	g := newAVScanGateway(t, srv.URL, mustAVScan(t, avscan.ActionQuarantine, true, eng))
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/huggingface/good/model/resolve/main/model.safetensors", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if string(rr.Body.Bytes()) != string(payload) {
		t.Error("served body does not match upstream")
	}
	if rr.Header().Get("X-AVScan-Decision") != "clean" {
		t.Errorf("X-AVScan-Decision = %q, want clean", rr.Header().Get("X-AVScan-Decision"))
	}
}

func TestAVScanGateFailClosedOnEngineDown(t *testing.T) {
	eng := &avTestEngine{err: avscan.ErrEngineUnavailable}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("some bytes"))
	}))
	defer srv.Close()

	g := newAVScanGateway(t, srv.URL, mustAVScan(t, avscan.ActionQuarantine, false, eng))
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/huggingface/x/model/resolve/main/pytorch_model.bin", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("fail-closed status = %d, want 403", rr.Code)
	}
}

func TestAVScanGateFailOpenOnEngineDown(t *testing.T) {
	eng := &avTestEngine{err: avscan.ErrEngineUnavailable}
	payload := []byte("served despite the scanner being down")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	g := newAVScanGateway(t, srv.URL, mustAVScan(t, avscan.ActionQuarantine, true, eng))
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/huggingface/x/model/resolve/main/pytorch_model.bin", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("fail-open status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-AVScan-Decision") != "degraded" {
		t.Errorf("X-AVScan-Decision = %q, want degraded", rr.Header().Get("X-AVScan-Decision"))
	}
}
