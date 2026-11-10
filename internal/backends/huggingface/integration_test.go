//go:build integration
// +build integration

// Integration tests for the Hugging Face backend against the live Hub
// (https://huggingface.co). Gated behind the `integration` build tag (and skipped
// when the network is unavailable) so the default `go test ./...` stays hermetic,
// mirroring the other backends' convention.
//
// Run with:
//
//	go test -tags integration ./internal/backends/huggingface/
package huggingface

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

const liveHub = "https://huggingface.co"

func liveBackend(t *testing.T, m *Metrics) *Backend {
	t.Helper()
	hc := &http.Client{Timeout: 60 * time.Second}
	b, err := New(Options{
		Name:        "huggingface-live",
		UpstreamURL: liveHub,
		Client:      upstream.NewWithHTTPClient(hc, "pullthrough-integration/1"),
		Metrics:     m,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func skipIfOffline(t *testing.T, err error) {
	t.Helper()
	var ne net.Error
	if errors.As(err, &ne) || errors.Is(err, context.DeadlineExceeded) {
		t.Skipf("network unavailable: %v", err)
	}
}

func liveFetch(t *testing.T, b *Backend, path string) (*backends.FetchResult, []byte) {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve(%q): %v", path, err)
	}
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		skipIfOffline(t, err)
		t.Fatalf("Fetch(%q): %v", path, err)
	}
	body, rerr := io.ReadAll(fr.Content)
	_ = fr.Content.Close()
	if rerr != nil {
		var mm *ChecksumMismatchError
		if errors.As(rerr, &mm) {
			t.Fatalf("live content failed verification: %v", rerr)
		}
		skipIfOffline(t, rerr)
		t.Fatalf("read body for %q: %v", path, rerr)
	}
	fr.Resolved = res
	return fr, body
}

// TestLiveModelFlow drives a real model end-to-end: read gpt2 metadata, then
// resolve its safetensors weight file and confirm the backend verified it against
// the Hub's advertised SHA-256 (X-Linked-Etag).
func TestLiveModelFlow(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)

	// 1. Model metadata carries the current commit SHA.
	_, metaBody := liveFetch(t, b, "/api/models/gpt2")
	var meta struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(metaBody, &meta); err != nil {
		t.Fatalf("metadata not JSON: %v (%s)", err, metaBody)
	}
	if meta.SHA == "" {
		t.Fatal("no commit sha in model metadata")
	}

	// 2. Resolve the safetensors weight pinned to that commit and verify SHA-256.
	fr, body := liveFetch(t, b, "/gpt2/resolve/"+meta.SHA+"/model.safetensors")
	if len(body) == 0 {
		t.Fatal("model.safetensors was empty")
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("safetensors was not SHA-256-verified: %q", fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if fr.Resolved.Metadata[MetaFormat] != formatSafetensors {
		t.Errorf("format metadata = %q, want safetensors", fr.Resolved.Metadata[MetaFormat])
	}
	if st := m.Stats(); st.FilesVerified < 1 || st.SafetensorsServed < 1 {
		t.Errorf("verification metrics not recorded: %+v", st)
	}
}
