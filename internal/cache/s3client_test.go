package cache

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSigV4SigningKeyVector checks sigV4SigningKey against AWS's published
// "derive a signing key for Signature Version 4" test vector. A correct derived
// key is the foundation of every signed request.
func TestSigV4SigningKeyVector(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	key := sigV4SigningKey(secret, "20120215", "us-east-1", "iam")
	want := "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
	if got := hex.EncodeToString(key); got != want {
		t.Fatalf("signing key = %s, want %s", got, want)
	}
}

func TestURIEncode(t *testing.T) {
	cases := map[string]string{
		"abcXYZ123": "abcXYZ123",
		"a b":       "a%20b",
		"a/b":       "a/b", // slash preserved when encodeSlash=false
		"a+b":       "a%2Bb",
		"k=v&x":     "k%3Dv%26x",
		"-_.~":      "-_.~",
		"café":      "caf%C3%A9",
		"100%/done": "100%25/done",
	}
	for in, want := range cases {
		if got := uriEncode(in, false); got != want {
			t.Errorf("uriEncode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEncodeCanonicalQuery(t *testing.T) {
	got := encodeCanonicalQuery([]queryParam{
		{"prefix", "meta/a b"},
		{"list-type", "2"},
		{"continuation-token", "tok+en/x"},
	})
	want := "continuation-token=tok%2Ben%2Fx&list-type=2&prefix=meta%2Fa%20b"
	if got != want {
		t.Fatalf("encodeCanonicalQuery = %q, want %q", got, want)
	}
}

func TestEncodeKeyPath(t *testing.T) {
	if got := encodeKeyPath("blobs/ab/cd/name with space"); got != "/blobs/ab/cd/name%20with%20space" {
		t.Fatalf("encodeKeyPath = %q", got)
	}
}

// memS3Server is a minimal in-memory S3-compatible HTTP server for exercising the
// real s3HTTPClient end to end (path-style addressing). It validates that the
// client sends an Authorization header and the required x-amz headers.
type memS3Server struct {
	mu      sync.Mutex
	objects map[string][]byte
	bucket  string
}

func newMemS3Server(bucket string) *memS3Server {
	return &memS3Server{objects: make(map[string][]byte), bucket: bucket}
}

func (m *memS3Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		http.Error(w, "missing Authorization", http.StatusForbidden)
		return
	}
	if r.Header.Get("X-Amz-Date") == "" || r.Header.Get("X-Amz-Content-Sha256") == "" {
		http.Error(w, "missing signing headers", http.StatusForbidden)
		return
	}
	// Path-style: /<bucket>[/<key>]
	path := strings.TrimPrefix(r.URL.Path, "/")
	prefixB := m.bucket
	if !strings.HasPrefix(path, prefixB) {
		http.Error(w, "wrong bucket", http.StatusNotFound)
		return
	}
	key := strings.TrimPrefix(path, prefixB)
	key = strings.TrimPrefix(key, "/")

	// ListObjectsV2 is a GET on the bucket with list-type=2.
	if r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2" {
		m.handleList(w, r)
		return
	}

	switch r.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.objects[key] = body
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	case http.MethodGet, http.MethodHead:
		m.mu.Lock()
		data, ok := m.objects[key]
		m.mu.Unlock()
		if !ok {
			http.Error(w, "<Error><Code>NoSuchKey</Code><Message>not found</Message></Error>", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("ETag", `"`+hex.EncodeToString([]byte(fmt.Sprintf("%x", len(data))))+`"`)
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	case http.MethodDelete:
		m.mu.Lock()
		delete(m.objects, key)
		m.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *memS3Server) handleList(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	m.mu.Lock()
	keys := make([]string, 0, len(m.objects))
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	objs := make(map[string]int, len(keys))
	for _, k := range keys {
		objs[k] = len(m.objects[k])
	}
	m.mu.Unlock()
	sort.Strings(keys)

	type contents struct {
		Key  string `xml:"Key"`
		Size int64  `xml:"Size"`
		ETag string `xml:"ETag"`
	}
	type result struct {
		XMLName     xml.Name   `xml:"ListBucketResult"`
		IsTruncated bool       `xml:"IsTruncated"`
		Contents    []contents `xml:"Contents"`
	}
	res := result{}
	for _, k := range keys {
		res.Contents = append(res.Contents, contents{Key: k, Size: int64(objs[k]), ETag: `"etag"`})
	}
	w.Header().Set("Content-Type", "application/xml")
	_ = xml.NewEncoder(w).Encode(res)
}

func newTestHTTPClient(t *testing.T, srv *httptest.Server, bucket string) *s3HTTPClient {
	t.Helper()
	c, err := newS3HTTPClient(S3ClientConfig{
		Endpoint:        srv.URL,
		Region:          "us-east-1",
		Bucket:          bucket,
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		UsePathStyle:    true,
		MaxRetries:      0,
		HTTPClient:      srv.Client(),
	})
	if err != nil {
		t.Fatalf("newS3HTTPClient: %v", err)
	}
	return c
}

func TestS3HTTPClientRoundTrip(t *testing.T) {
	mem := newMemS3Server("test-bucket")
	srv := httptest.NewServer(mem)
	defer srv.Close()
	c := newTestHTTPClient(t, srv, "test-bucket")
	ctx := context.Background()

	body := []byte("object body content")
	if err := c.putObject(ctx, "blobs/ab/cd/name", bytes.NewReader(body), int64(len(body)), hexSHA256(body), "application/octet-stream"); err != nil {
		t.Fatalf("putObject: %v", err)
	}

	attrs, err := c.headObject(ctx, "blobs/ab/cd/name")
	if err != nil {
		t.Fatalf("headObject: %v", err)
	}
	if attrs.Size != int64(len(body)) {
		t.Fatalf("head size = %d, want %d", attrs.Size, len(body))
	}

	rc, _, err := c.getObject(ctx, "blobs/ab/cd/name")
	if err != nil {
		t.Fatalf("getObject: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, body) {
		t.Fatalf("get body = %q, want %q", got, body)
	}

	if _, _, err := c.getObject(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("getObject missing = %v, want ErrNotFound", err)
	}
	if _, err := c.headObject(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("headObject missing = %v, want ErrNotFound", err)
	}

	if err := c.deleteObject(ctx, "blobs/ab/cd/name"); err != nil {
		t.Fatalf("deleteObject: %v", err)
	}
	if _, err := c.headObject(ctx, "blobs/ab/cd/name"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("headObject after delete = %v, want ErrNotFound", err)
	}
	// Delete of an absent key is idempotent.
	if err := c.deleteObject(ctx, "blobs/ab/cd/name"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func TestS3HTTPClientList(t *testing.T) {
	mem := newMemS3Server("b")
	srv := httptest.NewServer(mem)
	defer srv.Close()
	c := newTestHTTPClient(t, srv, "b")
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		k := fmt.Sprintf("meta/x/y/k%d.json", i)
		body := []byte(fmt.Sprintf("body-%d", i))
		if err := c.putObject(ctx, k, bytes.NewReader(body), int64(len(body)), hexSHA256(body), ""); err != nil {
			t.Fatalf("put %s: %v", k, err)
		}
	}
	// An object outside the prefix should be excluded.
	other := []byte("z")
	if err := c.putObject(ctx, "blobs/z", bytes.NewReader(other), 1, hexSHA256(other), ""); err != nil {
		t.Fatalf("put other: %v", err)
	}

	var got []string
	err := c.listObjects(ctx, "meta/", func(key string, _ objectAttrs) error {
		got = append(got, key)
		return nil
	})
	if err != nil {
		t.Fatalf("listObjects: %v", err)
	}
	sort.Strings(got)
	want := []string{"meta/x/y/k0.json", "meta/x/y/k1.json", "meta/x/y/k2.json"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("list = %v, want %v", got, want)
	}
}

// TestS3HTTPClientRetry verifies transient 5xx responses are retried and the
// PUT body is rewound between attempts.
func TestS3HTTPClientRetry(t *testing.T) {
	var attempts int
	var mu sync.Mutex
	var lastBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		attempts++
		n := attempts
		lastBody = body
		mu.Unlock()
		if n < 3 {
			http.Error(w, "<Error><Code>InternalError</Code></Error>", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c, err := newS3HTTPClient(S3ClientConfig{
		Endpoint:        srv.URL,
		Region:          "us-east-1",
		Bucket:          "b",
		AccessKeyID:     "a",
		SecretAccessKey: "s",
		UsePathStyle:    true,
		MaxRetries:      3,
		HTTPClient:      srv.Client(),
		sleep:           func(time.Duration) {}, // no real backoff in tests
	})
	if err != nil {
		t.Fatalf("newS3HTTPClient: %v", err)
	}
	payload := []byte("retry-me")
	if err := c.putObject(context.Background(), "k", bytes.NewReader(payload), int64(len(payload)), hexSHA256(payload), ""); err != nil {
		t.Fatalf("putObject: %v", err)
	}
	mu.Lock()
	gotAttempts, gotBody := attempts, lastBody
	mu.Unlock()
	if gotAttempts != 3 {
		t.Fatalf("attempts = %d, want 3", gotAttempts)
	}
	if !bytes.Equal(gotBody, payload) {
		t.Fatalf("body after retries = %q, want %q (rewind failed)", gotBody, payload)
	}
}
