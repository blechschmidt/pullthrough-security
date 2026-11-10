package cache

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

// condObjectStore is a minimal in-memory S3-compatible object store that honors
// the conditional headers (If-None-Match / If-Match) the lease client relies on,
// used to exercise S3ConditionalClient end-to-end over real HTTP+SigV4.
type condObjectStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func (s *condObjectStore) etag(key string) string {
	sum := md5.Sum(s.objects[key])
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func (s *condObjectStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := r.URL.Path // path-style: /bucket/key... ; we key on the full path

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		data, ok := s.objects[key]
		if !ok {
			http.Error(w, "<Error><Code>NoSuchKey</Code></Error>", http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", s.etag(key))
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	case http.MethodPut:
		_, exists := s.objects[key]
		if r.Header.Get("If-None-Match") == "*" && exists {
			http.Error(w, "<Error><Code>PreconditionFailed</Code></Error>", http.StatusPreconditionFailed)
			return
		}
		if m := r.Header.Get("If-Match"); m != "" {
			if !exists || m != s.etag(key) {
				http.Error(w, "<Error><Code>PreconditionFailed</Code></Error>", http.StatusPreconditionFailed)
				return
			}
		}
		body, _ := io.ReadAll(r.Body)
		s.objects[key] = body
		w.Header().Set("ETag", s.etag(key))
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		if m := r.Header.Get("If-Match"); m != "" {
			if _, ok := s.objects[key]; !ok {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if m != s.etag(key) {
				http.Error(w, "<Error><Code>PreconditionFailed</Code></Error>", http.StatusPreconditionFailed)
				return
			}
		}
		delete(s.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func newCondTestClient(t *testing.T) (*S3ConditionalClient, *condObjectStore) {
	t.Helper()
	store := &condObjectStore{objects: make(map[string][]byte)}
	srv := httptest.NewServer(store)
	t.Cleanup(srv.Close)
	cl, err := NewS3ConditionalClient(S3ClientConfig{
		Endpoint:        srv.URL,
		Region:          "us-east-1",
		Bucket:          "leases",
		AccessKeyID:     "AKIATEST",
		SecretAccessKey: "secret",
		UsePathStyle:    true,
	})
	if err != nil {
		t.Fatalf("NewS3ConditionalClient: %v", err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	return cl, store
}

func TestS3ConditionalCreateReplaceDelete(t *testing.T) {
	cl, _ := newCondTestClient(t)
	ctx := context.Background()
	key := "coord/leases/j.lease.json"

	etag1, err := cl.CreateIfAbsent(ctx, key, []byte(`{"v":1}`))
	if err != nil {
		t.Fatalf("CreateIfAbsent: %v", err)
	}
	if etag1 == "" {
		t.Fatal("expected non-empty etag from create")
	}

	// A second create must lose the optimistic race.
	if _, err := cl.CreateIfAbsent(ctx, key, []byte(`{"v":2}`)); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("second CreateIfAbsent err = %v, want ErrPreconditionFailed", err)
	}

	// Replace with the correct etag succeeds and changes the etag.
	etag2, err := cl.ReplaceIfMatch(ctx, key, []byte(`{"v":3}`), etag1)
	if err != nil {
		t.Fatalf("ReplaceIfMatch: %v", err)
	}
	if etag2 == etag1 {
		t.Error("expected etag to change after replace")
	}

	// Replace with the stale etag fails.
	if _, err := cl.ReplaceIfMatch(ctx, key, []byte(`{"v":4}`), etag1); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("stale ReplaceIfMatch err = %v, want ErrPreconditionFailed", err)
	}

	// Get returns the latest body + etag.
	data, etag, err := cl.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(data) != `{"v":3}` {
		t.Errorf("Get body = %s, want {\"v\":3}", data)
	}
	if etag != unquoteETag(etag2) {
		t.Errorf("Get etag = %q, want %q", etag, unquoteETag(etag2))
	}

	// Delete with the wrong etag fails; with the right one succeeds.
	if err := cl.DeleteIfMatch(ctx, key, etag1); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("stale DeleteIfMatch err = %v, want ErrPreconditionFailed", err)
	}
	if err := cl.DeleteIfMatch(ctx, key, etag); err != nil {
		t.Fatalf("DeleteIfMatch: %v", err)
	}
	if _, _, err := cl.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete err = %v, want ErrNotFound", err)
	}
}
