package cache

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// objectAttrs carries the subset of object metadata the store reads back from
// the object store. The content-addressable Record is persisted as a separate
// metadata object, so only size and ETag are surfaced here.
type objectAttrs struct {
	Size int64
	ETag string
}

// objectClient is the minimal object-storage surface S3Store depends on. It is
// an interface so the store can be unit-tested against an in-memory fake without
// a live S3 endpoint; the production implementation is s3HTTPClient.
//
// Implementations must be safe for concurrent use. getObject and headObject
// return ErrNotFound (possibly wrapped) when the key is absent. deleteObject is
// idempotent: removing an absent key is not an error (S3 DELETE semantics).
type objectClient interface {
	getObject(ctx context.Context, key string) (io.ReadCloser, objectAttrs, error)
	putObject(ctx context.Context, key string, body io.ReadSeeker, size int64, sha256hex, contentType string) error
	headObject(ctx context.Context, key string) (objectAttrs, error)
	deleteObject(ctx context.Context, key string) error
	// listObjects invokes fn for every object whose key begins with prefix,
	// paging transparently. Returning an error from fn aborts the listing.
	listObjects(ctx context.Context, prefix string, fn func(key string, attrs objectAttrs) error) error
	close() error
}

// emptyPayloadSHA256 is the hex SHA-256 of the empty string, used as the payload
// hash for bodyless requests (GET/HEAD/DELETE/LIST).
const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// S3ClientConfig configures the HTTP S3 client.
type S3ClientConfig struct {
	// Endpoint is the S3-compatible service endpoint, e.g.
	// "https://s3.us-east-1.amazonaws.com", "http://minio:9000", or
	// "https://storage.googleapis.com". When empty it defaults to the AWS
	// endpoint for Region.
	Endpoint string
	// Region is the signing region (e.g. "us-east-1"). Required by SigV4; MinIO
	// and GCS accept any value but it must be stable. Defaults to "us-east-1".
	Region string
	// Bucket is the target bucket. Required.
	Bucket string
	// AccessKeyID and SecretAccessKey are the static credentials. SessionToken is
	// optional (for temporary/STS credentials).
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	// UsePathStyle selects path-style addressing ("{endpoint}/{bucket}/{key}")
	// instead of virtual-host style ("{bucket}.{host}/{key}"). MinIO and most
	// non-AWS implementations require path-style; it is the safe default.
	UsePathStyle bool
	// InsecureSkipVerify disables TLS verification of the endpoint (test/self-
	// signed only).
	InsecureSkipVerify bool
	// CACertPool, when set, is the root pool used to verify the endpoint's TLS
	// certificate (for an internally-issued MinIO/object-store certificate).
	// Ignored when InsecureSkipVerify is true.
	CACertPool *x509.CertPool
	// MaxRetries bounds automatic retries of an idempotent request on transient
	// (5xx / network) errors. 0 means a single attempt. Defaults to 2.
	MaxRetries int
	// HTTPClient overrides the HTTP client. When nil a client with sensible
	// timeouts is constructed.
	HTTPClient *http.Client
	// now overrides the clock used for request signing (tests only).
	now func() time.Time
	// sleep overrides the backoff sleep between retries (tests only).
	sleep func(time.Duration)
}

// s3HTTPClient is a small, dependency-free S3 client. It speaks the S3 REST API
// directly with AWS Signature Version 4 request signing, which is understood by
// AWS S3, MinIO, Ceph RGW, and Google Cloud Storage's S3-compatible endpoint.
//
// It implements only the handful of operations the cache store needs
// (GET/PUT/HEAD/DELETE object and ListObjectsV2). Choosing a focused, auditable
// implementation over the full AWS SDK keeps the dependency surface of this
// supply-chain-security tool minimal and reviewable.
type s3HTTPClient struct {
	http         *http.Client
	endpoint     *url.URL
	region       string
	bucket       string
	accessKey    string
	secretKey    string
	sessionToken string
	usePathStyle bool
	maxRetries   int
	now          func() time.Time
	sleep        func(time.Duration)
}

var _ objectClient = (*s3HTTPClient)(nil)

// newS3HTTPClient validates the configuration and returns a ready client.
func newS3HTTPClient(cfg S3ClientConfig) (*s3HTTPClient, error) {
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, errors.New("cache: s3 client requires a bucket")
	}
	if strings.TrimSpace(cfg.AccessKeyID) == "" || strings.TrimSpace(cfg.SecretAccessKey) == "" {
		return nil, errors.New("cache: s3 client requires accessKeyId and secretAccessKey")
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = "us-east-1"
	}
	endpointStr := strings.TrimSpace(cfg.Endpoint)
	if endpointStr == "" {
		endpointStr = "https://s3." + region + ".amazonaws.com"
	}
	if !strings.Contains(endpointStr, "://") {
		// Tolerate a bare host[:port]; assume TLS.
		endpointStr = "https://" + endpointStr
	}
	endpoint, err := url.Parse(endpointStr)
	if err != nil {
		return nil, fmt.Errorf("cache: parsing s3 endpoint %q: %w", cfg.Endpoint, err)
	}
	if endpoint.Host == "" {
		return nil, fmt.Errorf("cache: s3 endpoint %q has no host", cfg.Endpoint)
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		transport := &http.Transport{
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
		}
		if cfg.InsecureSkipVerify || cfg.CACertPool != nil {
			tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
			if cfg.InsecureSkipVerify {
				tlsCfg.InsecureSkipVerify = true
			} else {
				tlsCfg.RootCAs = cfg.CACertPool
			}
			transport.TLSClientConfig = tlsCfg
		}
		httpClient = &http.Client{Transport: transport}
	}

	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = 2
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	sleep := cfg.sleep
	if sleep == nil {
		sleep = time.Sleep
	}

	return &s3HTTPClient{
		http:         httpClient,
		endpoint:     endpoint,
		region:       region,
		bucket:       cfg.Bucket,
		accessKey:    cfg.AccessKeyID,
		secretKey:    cfg.SecretAccessKey,
		sessionToken: cfg.SessionToken,
		usePathStyle: cfg.UsePathStyle,
		maxRetries:   maxRetries,
		now:          now,
		sleep:        sleep,
	}, nil
}

// objectURL builds the request URL for a given object key, honoring path-style
// vs virtual-host addressing. The returned URL has its RawPath set so the
// SigV4 canonical URI exactly matches what is transmitted.
func (c *s3HTTPClient) objectURL(key string) *url.URL {
	u := *c.endpoint
	var encodedPath string
	if c.usePathStyle {
		encodedPath = "/" + c.bucket + encodeKeyPath(key)
		u.Host = c.endpoint.Host
	} else {
		u.Host = c.bucket + "." + c.endpoint.Host
		encodedPath = encodeKeyPath(key)
	}
	u.Path = decodeForGo(encodedPath)
	u.RawPath = encodedPath
	return &u
}

// bucketURL builds the request URL for a bucket-level operation (ListObjectsV2).
func (c *s3HTTPClient) bucketURL() *url.URL {
	u := *c.endpoint
	if c.usePathStyle {
		u.Path = "/" + c.bucket
		u.RawPath = "/" + c.bucket
		u.Host = c.endpoint.Host
	} else {
		u.Host = c.bucket + "." + c.endpoint.Host
		u.Path = "/"
		u.RawPath = "/"
	}
	return &u
}

func (c *s3HTTPClient) getObject(ctx context.Context, key string) (io.ReadCloser, objectAttrs, error) {
	resp, err := c.do(ctx, http.MethodGet, c.objectURL(key), nil, 0, emptyPayloadSHA256, "")
	if err != nil {
		return nil, objectAttrs{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		drainClose(resp.Body)
		return nil, objectAttrs{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, objectAttrs{}, c.statusError("GET", key, resp)
	}
	attrs := objectAttrs{ETag: strings.Trim(resp.Header.Get("ETag"), `"`)}
	if resp.ContentLength >= 0 {
		attrs.Size = resp.ContentLength
	}
	return resp.Body, attrs, nil
}

func (c *s3HTTPClient) headObject(ctx context.Context, key string) (objectAttrs, error) {
	resp, err := c.do(ctx, http.MethodHead, c.objectURL(key), nil, 0, emptyPayloadSHA256, "")
	if err != nil {
		return objectAttrs{}, err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return objectAttrs{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return objectAttrs{}, c.statusError("HEAD", key, resp)
	}
	attrs := objectAttrs{ETag: strings.Trim(resp.Header.Get("ETag"), `"`)}
	if resp.ContentLength >= 0 {
		attrs.Size = resp.ContentLength
	}
	return attrs, nil
}

func (c *s3HTTPClient) putObject(ctx context.Context, key string, body io.ReadSeeker, size int64, sha256hex, contentType string) error {
	resp, err := c.do(ctx, http.MethodPut, c.objectURL(key), body, size, sha256hex, contentType)
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.statusError("PUT", key, resp)
	}
	return nil
}

func (c *s3HTTPClient) deleteObject(ctx context.Context, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, c.objectURL(key), nil, 0, emptyPayloadSHA256, "")
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)
	// S3 DELETE is idempotent: 204 on success, and a missing key also yields 204
	// (or, on some implementations, 404 — treated as success here).
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return c.statusError("DELETE", key, resp)
}

// listResult mirrors the ListObjectsV2 XML response.
type listResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key  string `xml:"Key"`
		Size int64  `xml:"Size"`
		ETag string `xml:"ETag"`
	} `xml:"Contents"`
}

func (c *s3HTTPClient) listObjects(ctx context.Context, prefix string, fn func(key string, attrs objectAttrs) error) error {
	continuation := ""
	for {
		u := c.bucketURL()
		q := []queryParam{
			{"list-type", "2"},
			{"max-keys", "1000"},
		}
		if prefix != "" {
			q = append(q, queryParam{"prefix", prefix})
		}
		if continuation != "" {
			q = append(q, queryParam{"continuation-token", continuation})
		}
		u.RawQuery = encodeCanonicalQuery(q)

		resp, err := c.do(ctx, http.MethodGet, u, nil, 0, emptyPayloadSHA256, "")
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			err := c.statusError("LIST", prefix, resp)
			return err
		}
		var result listResult
		decErr := xml.NewDecoder(resp.Body).Decode(&result)
		drainClose(resp.Body)
		if decErr != nil {
			return fmt.Errorf("cache: decoding s3 list response: %w", decErr)
		}
		for _, obj := range result.Contents {
			if err := fn(obj.Key, objectAttrs{Size: obj.Size, ETag: strings.Trim(obj.ETag, `"`)}); err != nil {
				return err
			}
		}
		if !result.IsTruncated || result.NextContinuationToken == "" {
			return nil
		}
		continuation = result.NextContinuationToken
	}
}

func (c *s3HTTPClient) close() error {
	c.http.CloseIdleConnections()
	return nil
}

// do executes a signed request, retrying idempotent failures on transient
// errors. When body is non-nil it must be seekable so a retry can rewind it.
func (c *s3HTTPClient) do(ctx context.Context, method string, u *url.URL, body io.ReadSeeker, size int64, payloadHash, contentType string) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			if body != nil {
				if _, err := body.Seek(0, io.SeekStart); err != nil {
					return nil, fmt.Errorf("cache: rewinding s3 request body for retry: %w", err)
				}
			}
			// Linear backoff; honors context cancellation.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			c.sleep(time.Duration(attempt) * 50 * time.Millisecond)
		}

		req, err := c.newRequest(ctx, method, u, body, size, payloadHash, contentType)
		if err != nil {
			return nil, err
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			if attempt < c.maxRetries {
				continue
			}
			return nil, fmt.Errorf("cache: s3 %s %s: %w", method, u.Redacted(), err)
		}
		if resp.StatusCode >= 500 && attempt < c.maxRetries {
			drainClose(resp.Body)
			lastErr = fmt.Errorf("s3 returned status %d", resp.StatusCode)
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("cache: s3 %s %s failed after retries: %w", method, u.Redacted(), lastErr)
}

// newRequest builds and signs a single request.
func (c *s3HTTPClient) newRequest(ctx context.Context, method string, u *url.URL, body io.Reader, size int64, payloadHash, contentType string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	c.sign(req, payloadHash, c.now().UTC())
	return req, nil
}

// sign applies AWS Signature Version 4 to req using the canonical request /
// string-to-sign / signing-key construction.
func (c *s3HTTPClient) sign(req *http.Request, payloadHash string, t time.Time) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if c.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.sessionToken)
	}
	host := req.URL.Host
	req.Host = host

	// Signed headers: host plus the x-amz-* headers we set.
	type hdr struct{ name, value string }
	headers := []hdr{
		{"host", host},
		{"x-amz-content-sha256", payloadHash},
		{"x-amz-date", amzDate},
	}
	if c.sessionToken != "" {
		headers = append(headers, hdr{"x-amz-security-token", c.sessionToken})
	}
	sort.Slice(headers, func(i, j int) bool { return headers[i].name < headers[j].name })

	var canonicalHeaders strings.Builder
	signedHeaderNames := make([]string, 0, len(headers))
	for _, h := range headers {
		canonicalHeaders.WriteString(h.name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(h.value))
		canonicalHeaders.WriteByte('\n')
		signedHeaderNames = append(signedHeaderNames, h.name)
	}
	signedHeaders := strings.Join(signedHeaderNames, ";")

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		req.URL.RawQuery,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, c.region, "s3", "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	signingKey := sigV4SigningKey(c.secretKey, dateStamp, c.region, "s3")
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	authorization := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.accessKey, scope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", authorization)
}

// statusError reads (a bounded prefix of) an error response body and returns a
// descriptive error, mapping S3's <Error><Code> when present.
func (c *s3HTTPClient) statusError(op, key string, resp *http.Response) error {
	defer drainClose(resp.Body)
	const maxErrBody = 8 << 10
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
	var s3e struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if err := xml.Unmarshal(data, &s3e); err == nil && s3e.Code != "" {
		return fmt.Errorf("cache: s3 %s %q: %s: %s (status %d)", op, key, s3e.Code, s3e.Message, resp.StatusCode)
	}
	return fmt.Errorf("cache: s3 %s %q: unexpected status %d: %s", op, key, resp.StatusCode, strings.TrimSpace(string(data)))
}

// --- SigV4 / encoding helpers ----------------------------------------------

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// sigV4SigningKey derives the SigV4 signing key from the secret access key.
func sigV4SigningKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

type queryParam struct {
	key   string
	value string
}

// encodeCanonicalQuery encodes query parameters per the SigV4 canonical-query
// rules: sorted by key, RFC3986-encoded, joined with '&'. Because we always sign
// what we send, the same encoding is used for the wire query string.
func encodeCanonicalQuery(params []queryParam) string {
	sorted := make([]queryParam, len(params))
	copy(sorted, params)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].key == sorted[j].key {
			return sorted[i].value < sorted[j].value
		}
		return sorted[i].key < sorted[j].key
	})
	var b strings.Builder
	for i, p := range sorted {
		if i > 0 {
			b.WriteByte('&')
		}
		// Query keys and values encode '/' (unlike path segments), per the SigV4
		// canonical-query rules.
		b.WriteString(uriEncode(p.key, true))
		b.WriteByte('=')
		b.WriteString(uriEncode(p.value, true))
	}
	return b.String()
}

// encodeKeyPath encodes an object key for use as a URL path, preserving '/'
// separators between encoded segments and prefixing a leading '/'.
func encodeKeyPath(key string) string {
	key = strings.TrimPrefix(key, "/")
	segments := strings.Split(key, "/")
	for i, s := range segments {
		segments[i] = uriEncode(s, false)
	}
	return "/" + strings.Join(segments, "/")
}

// uriEncode implements AWS's URI encoding: unreserved characters
// (A-Z a-z 0-9 - _ . ~) pass through; everything else is percent-encoded with
// uppercase hex. When encodeSlash is false, '/' is left intact (path segments
// are encoded individually so this is moot, but kept for clarity).
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~':
			b.WriteByte(ch)
		case ch == '/' && !encodeSlash:
			b.WriteByte('/')
		default:
			b.WriteByte('%')
			b.WriteByte(upperHex(ch >> 4))
			b.WriteByte(upperHex(ch & 0x0f))
		}
	}
	return b.String()
}

func upperHex(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'A' + (n - 10)
}

// decodeForGo converts a percent-encoded path back to its raw form for url.Path.
// net/http re-encodes from URL.RawPath only when it is a valid encoding of
// URL.Path, so we must keep the two consistent.
func decodeForGo(encoded string) string {
	if unescaped, err := url.PathUnescape(encoded); err == nil {
		return unescaped
	}
	return encoded
}

// drainClose drains and closes a response body so the connection can be reused.
func drainClose(rc io.ReadCloser) {
	if rc == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, 1<<20))
	_ = rc.Close()
}
