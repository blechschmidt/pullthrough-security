package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrPreconditionFailed reports that a conditional write lost the optimistic-
// concurrency race: the object already existed (create-if-absent) or was
// modified/removed concurrently (replace/delete-if-match). Callers treat it as a
// "lost the race" signal rather than a hard error.
var ErrPreconditionFailed = errors.New("cache: s3 conditional write precondition failed")

// S3ConditionalClient is a small conditional-write wrapper over the dependency-
// free SigV4 S3 client that backs S3Store. It exposes the optimistic-concurrency
// object operations the distributed-coordination lease store needs (Task 56):
// create-if-absent, replace-if-match, and delete-if-match, built on S3's
// conditional request headers (If-None-Match / If-Match). It deliberately reuses
// the same auditable SigV4 signing as the cache store rather than introducing a
// second S3 implementation.
//
// Compare-and-swap leasing requires an object store that honors conditional
// writes. AWS S3 (If-None-Match since Nov 2024, If-Match shortly after), MinIO,
// and Ceph RGW do. An older S3 implementation that silently ignores the headers
// is unsafe for leader election and must not be used as a coordination backend —
// it would let two replicas both believe they hold the lease.
type S3ConditionalClient struct {
	c *s3HTTPClient
}

// NewS3ConditionalClient builds a conditional-write client from the same
// configuration used for the cache S3 store.
func NewS3ConditionalClient(cfg S3ClientConfig) (*S3ConditionalClient, error) {
	c, err := newS3HTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	return &S3ConditionalClient{c: c}, nil
}

// Get downloads the object body and its current ETag. It returns ErrNotFound
// (the cache package's sentinel) when the key is absent.
func (l *S3ConditionalClient) Get(ctx context.Context, key string) ([]byte, string, error) {
	body, attrs, err := l.c.getObject(ctx, key)
	if err != nil {
		return nil, "", err
	}
	defer drainClose(body)
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, "", err
	}
	return data, attrs.ETag, nil
}

// CreateIfAbsent writes data only if no object exists at key (If-None-Match: *),
// returning the new object's ETag. It returns ErrPreconditionFailed when the key
// already exists.
func (l *S3ConditionalClient) CreateIfAbsent(ctx context.Context, key string, data []byte) (string, error) {
	return l.conditionalPut(ctx, key, data, map[string]string{"If-None-Match": "*"})
}

// ReplaceIfMatch overwrites the object only if its current ETag equals etag
// (If-Match: <etag>), returning the new ETag. It returns ErrPreconditionFailed
// when the stored object changed (or vanished) concurrently.
func (l *S3ConditionalClient) ReplaceIfMatch(ctx context.Context, key string, data []byte, etag string) (string, error) {
	return l.conditionalPut(ctx, key, data, map[string]string{"If-Match": quoteETag(etag)})
}

// DeleteIfMatch removes the object only if its current ETag equals etag. A
// missing object is treated as success (already gone). It returns
// ErrPreconditionFailed when the stored object changed concurrently.
func (l *S3ConditionalClient) DeleteIfMatch(ctx context.Context, key, etag string) error {
	resp, err := l.c.condDo(ctx, http.MethodDelete, l.c.objectURL(key), nil, "", map[string]string{"If-Match": quoteETag(etag)})
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusNotFound:
		return nil
	case http.StatusPreconditionFailed, http.StatusConflict:
		return ErrPreconditionFailed
	default:
		return l.c.statusError("DELETE-IF-MATCH", key, resp)
	}
}

// Close releases idle connections.
func (l *S3ConditionalClient) Close() error { return l.c.close() }

// conditionalPut performs a single signed PUT carrying the given conditional
// headers and resolves the resulting ETag (reading it back with a HEAD when the
// store omits it from the PUT response, as some S3-compatibles do).
func (l *S3ConditionalClient) conditionalPut(ctx context.Context, key string, data []byte, headers map[string]string) (string, error) {
	resp, err := l.c.condDo(ctx, http.MethodPut, l.c.objectURL(key), data, "application/json", headers)
	if err != nil {
		return "", err
	}
	defer drainClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		etag := unquoteETag(resp.Header.Get("ETag"))
		if etag == "" {
			// The store did not echo the ETag; read it back so the caller has a
			// usable CAS token for the next renew.
			if attrs, herr := l.c.headObject(ctx, key); herr == nil {
				etag = attrs.ETag
			}
		}
		return etag, nil
	case http.StatusPreconditionFailed, http.StatusConflict:
		return "", ErrPreconditionFailed
	default:
		return "", l.c.statusError("PUT-CONDITIONAL", key, resp)
	}
}

// condDo builds, signs, and executes a single conditional request. Conditional
// headers (If-Match / If-None-Match) are intentionally left out of the SigV4
// signed-header set — S3 only requires signing host and the x-amz-* headers — so
// they are applied after signing. Unlike s3HTTPClient.do it does not retry: a
// retried conditional write whose first response was lost would be misread as a
// precondition failure, so the caller's campaign loop owns the retry instead.
func (c *s3HTTPClient) condDo(ctx context.Context, method string, u *url.URL, body []byte, contentType string, headers map[string]string) (*http.Response, error) {
	var rdr io.Reader
	size := int64(0)
	payloadHash := emptyPayloadSHA256
	if body != nil {
		rdr = bytes.NewReader(body)
		size = int64(len(body))
		sum := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(sum[:])
	}
	req, err := c.newRequest(ctx, method, u, rdr, size, payloadHash, contentType)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.http.Do(req)
}

// quoteETag wraps a bare ETag in the double quotes S3 expects on the wire,
// tolerating an already-quoted value.
func quoteETag(etag string) string {
	etag = strings.TrimSpace(etag)
	if etag == "" || etag == "*" {
		return etag
	}
	if strings.HasPrefix(etag, `"`) && strings.HasSuffix(etag, `"`) {
		return etag
	}
	return `"` + etag + `"`
}

// unquoteETag strips the surrounding quotes S3 returns on ETag headers.
func unquoteETag(etag string) string {
	return strings.Trim(strings.TrimSpace(etag), `"`)
}
