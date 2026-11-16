package fullmirror

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

// This file holds what every feed adapter (Task 190) is built from: reading
// its options and locating its feed, the requests it makes to the registry and
// through the proxy's gated pipeline, the cursor encoding, the files it keeps
// in Env.Dir, and the conversion of repos/locate's plans into the artifacts
// the engine fetches.
//
// Two rules hold for every adapter. A registry is untrusted input: every body
// is read up to a bound, every field is checked before it names a path, and a
// document past its bound is refused rather than truncated. And no adapter
// builds an artifact URL itself: the paths come from the backend's own path
// builders, from the URLs the backend wrote into the documents it rewrote for
// clients, or from repos/locate — the code the release pinner (Task 180) holds
// to every backend's parser — so the mirror fetches exactly the paths clients
// request.

// Bounds on what an adapter reads.
const (
	// maxFeedPage bounds one page of a change feed.
	maxFeedPage = 64 << 20
	// maxMetadataDoc bounds one package's metadata document: an npm packument
	// of a package with thousands of versions runs to tens of megabytes.
	maxMetadataDoc = 256 << 20
	// holdAfterRefusal is the wait a metadata read asks for when the pipeline
	// refused it without judging the package (access control, a lockdown, a
	// snapshot freeze): every read of the upstream would be refused alike.
	holdAfterRefusal = 5 * time.Minute
	// maxRetryAfter bounds a registry's Retry-After.
	maxRetryAfter = 24 * time.Hour
)

// errValidationOnly is what an adapter built by Check answers if it is used.
var errValidationOnly = errors.New("fullmirror: the feed adapter was built to validate the configuration only")

// options are an adapter's options (Env.Options), trimmed.
type options map[string]string

// parseOptions reads env.Options, refusing a key the adapter does not know:
// a misspelt option would otherwise be ignored and the default silently used.
func parseOptions(env Env, known ...string) (options, error) {
	allowed := map[string]bool{}
	for _, k := range known {
		allowed[k] = true
	}
	keys := make([]string, 0, len(env.Options))
	for k := range env.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := options{}
	for _, k := range keys {
		if !allowed[k] {
			list := append([]string(nil), known...)
			sort.Strings(list)
			return nil, fmt.Errorf("the %s feed has no option %q (known: %s)", env.Type, k, strings.Join(list, ", "))
		}
		v := strings.TrimSpace(env.Options[k])
		if strings.ContainsAny(v, "\x00\r\n") {
			return nil, fmt.Errorf("the %s feed's option %q contains a control character", env.Type, k)
		}
		out[k] = v
	}
	return out, nil
}

// get returns an option's value, or def when it is unset or empty.
func (o options) get(key, def string) string {
	if v := o[key]; v != "" {
		return v
	}
	return def
}

// oneOf returns an option's value checked against the allowed values (the
// first is the default).
func (o options) oneOf(key string, allowed ...string) (string, error) {
	v := strings.ToLower(o.get(key, allowed[0]))
	for _, a := range allowed {
		if v == a {
			return v, nil
		}
	}
	return "", fmt.Errorf("option %q is %q; want one of %s", key, v, strings.Join(allowed, ", "))
}

// parseBaseURL reads an absolute http(s) URL without credentials, query or
// fragment: an upstream's or a feed's base. Plain http is allowed (a private
// registry inside the network, the tests); the egress policy decides where
// the proxy may connect.
func parseBaseURL(what, raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("no %s", what)
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%s %q is not a URL: %w", what, raw, err)
	case u.Scheme != "https" && u.Scheme != "http":
		return nil, fmt.Errorf("%s %q is not an http(s) URL", what, raw)
	case u.Host == "":
		return nil, fmt.Errorf("%s %q has no host", what, raw)
	case u.User != nil:
		return nil, fmt.Errorf("%s carries credentials; configure them on the upstream instead", what)
	case u.RawQuery != "" || u.Fragment != "":
		return nil, fmt.Errorf("%s %q must not carry a query or fragment", what, raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// hostIs reports whether u's host (without port) is one of hosts.
func hostIs(u *url.URL, hosts ...string) bool {
	h := strings.ToLower(u.Hostname())
	for _, x := range hosts {
		if h == x {
			return true
		}
	}
	return false
}

// join appends path segments (already escaped where needed) to a base URL.
func join(base *url.URL, path string) string {
	b := *base
	b.Path = strings.TrimRight(b.Path, "/") + "/" + strings.TrimLeft(path, "/")
	b.RawPath = ""
	return b.String()
}

// kit is what an adapter makes its requests with.
type kit struct {
	env Env
	// upstream is Env.URL, parsed; its origin is the only one Authorize is
	// called for.
	upstream *url.URL
}

func newKit(env Env) (kit, error) {
	u, err := parseBaseURL("the upstream URL", env.URL)
	if err != nil {
		return kit{}, err
	}
	return kit{env: env, upstream: u}, nil
}

// sameOrigin reports whether u is on the upstream's origin.
func (k kit) sameOrigin(u *url.URL) bool {
	return strings.EqualFold(u.Scheme, k.upstream.Scheme) && strings.EqualFold(u.Host, k.upstream.Host)
}

// do sends one request. The caller closes the body.
func (k kit) do(ctx context.Context, method, rawURL string, body io.Reader, hdr http.Header) (*http.Response, error) {
	if k.env.HTTP == nil {
		return nil, errValidationOnly
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("building the request for %s: %w", rawURL, err))
	}
	for name, vals := range hdr {
		for _, v := range vals {
			req.Header.Add(name, v)
		}
	}
	if k.env.UserAgent != "" {
		req.Header.Set("User-Agent", k.env.UserAgent)
	}
	if k.env.Authorize != nil && k.sameOrigin(req.URL) {
		k.env.Authorize(req)
	}
	resp, err := k.env.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, rawURL, err)
	}
	return resp, nil
}

// get fetches rawURL and returns the body of a 2xx answer, at most limit
// bytes; any other answer is an error httpStatusError classifies.
func (k kit) get(ctx context.Context, rawURL string, hdr http.Header, limit int64) ([]byte, *http.Response, error) {
	resp, err := k.do(ctx, http.MethodGet, rawURL, nil, hdr)
	if err != nil {
		return nil, nil, err
	}
	defer drain(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, resp, httpStatusError(rawURL, resp)
	}
	body, err := readLimited(resp.Body, limit)
	if err != nil {
		return nil, resp, fmt.Errorf("reading %s: %w", rawURL, err)
	}
	return body, resp, nil
}

// getJSON fetches rawURL and decodes its JSON body into v.
func (k kit) getJSON(ctx context.Context, rawURL string, limit int64, v any) (*http.Response, error) {
	body, resp, err := k.get(ctx, rawURL, http.Header{"Accept": {"application/json"}}, limit)
	if err != nil {
		return resp, err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return resp, Permanent(fmt.Errorf("%s is not the JSON document expected: %w", rawURL, err))
	}
	return resp, nil
}

// drain discards what is left of a body (up to a bound, so a connection can
// be reused) and closes it.
func drain(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 64<<10))
	_ = body.Close()
}

// errTooLarge marks a document past its bound.
var errTooLarge = errors.New("the document is larger than the adapter reads")

// readLimited reads r to its end, failing (permanently) past limit bytes.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, Permanent(fmt.Errorf("%w (%d bytes)", errTooLarge, limit))
	}
	return data, nil
}

// httpStatusError classifies a registry's answer: a 404 or 410 is a package (or
// a feed) the registry does not have, a 429 or 503 asks for a wait, another
// 5xx is worth retrying, any other answer is not.
func httpStatusError(what string, resp *http.Response) error {
	err := fmt.Errorf("%s: %s", what, resp.Status)
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return Permanent(fmt.Errorf("%w: not found", err))
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable:
		if d, ok := retryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
			return RetryAfter(err, d)
		}
		return err
	case resp.StatusCode >= 500:
		return err
	}
	return Permanent(err)
}

// retryAfter parses a Retry-After header: seconds or an HTTP date, at most a
// day.
func retryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	var d time.Duration
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs <= 0 {
			return 0, false
		}
		if secs > int64(maxRetryAfter/time.Second) {
			secs = int64(maxRetryAfter / time.Second)
		}
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	} else {
		return 0, false
	}
	if d <= 0 {
		return 0, false
	}
	if d > maxRetryAfter {
		d = maxRetryAfter
	}
	return d, true
}

// boundedBuffer collects a body up to a limit and fails the write past it.
type boundedBuffer struct {
	buf      bytes.Buffer
	limit    int64
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if int64(b.buf.Len())+int64(len(p)) > b.limit {
		b.exceeded = true
		return 0, errTooLarge
	}
	return b.buf.Write(p)
}

// read fetches a path of the upstream's mount through the proxy's gated serve
// pipeline (Env.Read): the document as the backend serves it to clients, with
// the upstream's credentials, mirrors and URL rewriting applied.
func (k kit) read(ctx context.Context, path, accept string, limit int64) ([]byte, error) {
	if k.env.Read == nil {
		return nil, errValidationOnly
	}
	buf := &boundedBuffer{limit: limit}
	res, err := k.env.Read(ctx, path, accept, buf)
	if buf.exceeded {
		return nil, Permanent(fmt.Errorf("reading %s: %w (%d bytes)", path, errTooLarge, limit))
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s through the proxy: %w", path, err)
	}
	if res.Status == http.StatusOK {
		return buf.buf.Bytes(), nil
	}
	return nil, readError(path, res)
}

// readError classifies an answer of the gated pipeline that is not a 200.
func readError(path string, res FetchResult) error {
	if res.Gate != "" {
		err := fmt.Errorf("reading %s: the %s gate refused it (%s): %s", path, res.Gate, firstNonEmpty(res.Code, "no code"), cleanMessage(res.Reason))
		switch classifyRefusal(res) {
		case refusalLockdown, refusalHold:
			// Not a verdict on the package: every read would be refused.
			return RetryAfter(err, holdAfterRefusal)
		case refusalLater:
			d := res.RetryAfter
			if d <= 0 {
				d = time.Minute
			}
			return RetryAfter(err, d)
		}
		return Permanent(err)
	}
	err := fmt.Errorf("reading %s: status %d", path, res.Status)
	if res.Reason != "" {
		err = fmt.Errorf("%w: %s", err, cleanMessage(res.Reason))
	}
	switch {
	case res.Status == http.StatusNotFound || res.Status == http.StatusGone:
		return Permanent(fmt.Errorf("%w (not found)", err))
	case res.Status == http.StatusTooManyRequests || res.Status == http.StatusServiceUnavailable:
		if res.RetryAfter > 0 {
			return RetryAfter(err, res.RetryAfter)
		}
		return err
	case res.Status >= 500 || res.Status == 0:
		return err
	}
	return Permanent(err)
}

// readJSON reads a document through the pipeline and decodes it into v.
func (k kit) readJSON(ctx context.Context, path, accept string, limit int64, v any) error {
	body, err := k.read(ctx, path, accept, limit)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return Permanent(fmt.Errorf("%s is not the JSON document expected: %w", path, err))
	}
	return nil
}

// docFetcher serves repos/locate's index reads from the gated pipeline,
// keeping each document for the life of the fetcher: locating every version
// of a package reads its index once.
type docFetcher struct {
	k    kit
	mu   sync.Mutex
	docs map[string][]byte
}

func (k kit) fetcher() *docFetcher { return &docFetcher{k: k, docs: map[string][]byte{}} }

// FetchDocument implements locate.Fetcher.
func (f *docFetcher) FetchDocument(ctx context.Context, _ string, path, accept string) (locate.Document, error) {
	key := path + "\x00" + accept
	f.mu.Lock()
	body, ok := f.docs[key]
	f.mu.Unlock()
	if !ok {
		var err error
		if body, err = f.k.read(ctx, path, accept, maxMetadataDoc); err != nil {
			return locate.Document{}, err
		}
		f.mu.Lock()
		f.docs[key] = body
		f.mu.Unlock()
	}
	ct := ""
	if t := bytes.TrimSpace(body); len(t) > 0 && (t[0] == '{' || t[0] == '[') {
		ct = "application/json"
	}
	return locate.Document{Status: http.StatusOK, ContentType: ct, Body: body}, nil
}

// locateUpstream is the upstream as repos/locate knows it.
func (k kit) locateUpstream() locate.Upstream {
	return locate.Upstream{Name: k.env.Upstream, Type: k.env.Type, URLs: []string{k.env.URL}, Settings: k.env.Settings}
}

// locate asks repos/locate for the artifacts of one version, as the release
// pinner does for a lock file's dependency: the paths are the backend's own.
// fetch reads the indexes a locator needs (nil when it needs none). Files the
// locator could not place are left out; a version none of whose files could
// be placed is a permanent error.
func (k kit) locate(ctx context.Context, dep lockfiles.Dependency, fetch locate.Fetcher) ([]Artifact, error) {
	dep.Type = k.env.Type
	dep.Upstream = k.env.Upstream
	plan, err := locate.Locate(ctx, locate.Env{Upstreams: []locate.Upstream{k.locateUpstream()}, Fetch: fetch}, dep)
	if err != nil {
		if locate.IsUnsupported(err) {
			return nil, Permanent(err)
		}
		return nil, err
	}
	var out []Artifact
	var first string
	for _, a := range plan.Artifacts {
		if a.Error != "" {
			if first == "" {
				first = a.Error
			}
			continue
		}
		out = append(out, Artifact{Path: a.Path, Accept: a.Accept})
	}
	if len(out) == 0 {
		return nil, Permanent(fmt.Errorf("no file of %s %s can be fetched through the proxy: %s", dep.Name, dep.Version, firstNonEmpty(first, "the locator named none")))
	}
	return out, nil
}

// proxyPath maps a URL the backend wrote into a document it rewrote for
// clients (or a URL beneath the upstream) to the path the proxy serves it at.
func (k kit) proxyPath(raw string) (string, bool) {
	p, ok := locate.ProxyPath(k.locateUpstream(), raw)
	if !ok || !validArtifactPath(p) {
		return "", false
	}
	return p, true
}

// validArtifactPath reports whether p is a path the engine may request: absolute,
// no query or fragment, no control character, no dot segment once decoded.
func validArtifactPath(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) > 4096 || strings.ContainsAny(p, "?#\\") {
		return false
	}
	dec, err := url.PathUnescape(p)
	if err != nil {
		return false
	}
	for _, r := range dec {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	for _, seg := range strings.Split(dec[1:], "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// cleanName reports whether a package name a feed reports is one the engine
// can carry (validateBatch's rule): non-empty, bounded, no control character.
func cleanName(s string) bool {
	if s == "" || len(s) > 1024 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// orderReleases sorts releases oldest first by the ecosystem's version order
// when the proxy knows it; versions that do not parse keep the registry's
// order ahead of those that do.
func orderReleases(typ string, rels []Release) {
	scheme, ok := versions.For(typ)
	if !ok {
		return
	}
	parsed := make([]versions.Version, len(rels))
	for i, r := range rels {
		if v, err := scheme.Parse(r.Version); err == nil {
			parsed[i] = v
		}
	}
	idx := make([]int, len(rels))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		va, vb := parsed[idx[a]], parsed[idx[b]]
		switch {
		case va == nil && vb == nil:
			return false
		case va == nil:
			return true
		case vb == nil:
			return false
		}
		return scheme.Compare(va, vb) < 0
	})
	out := make([]Release, len(rels))
	for i, j := range idx {
		out[i] = rels[j]
	}
	copy(rels, out)
}

// cursorFormat is the format every adapter's cursor carries ("npm/1"): a
// cursor of another adapter, or of an older format, is not trusted.
func cursorFormat(typ string, version int) string { return typ + "/" + strconv.Itoa(version) }

// encodeCursor renders a cursor as JSON. The cursor types are plain structs of
// strings and numbers; marshalling them does not fail.
func encodeCursor(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("fullmirror: encoding a cursor: %v", err))
	}
	return string(b)
}

// decodeCursor reads a cursor encodeCursor wrote, checking its format. A
// cursor that does not read — another adapter's, an older format's, a damaged
// state file's — is ErrCursorInvalid: the engine enumerates the registry
// again rather than trusting it.
func decodeCursor(s, format string, v interface{ cursorFormat() string }) error {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrCursorInvalid, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing data", ErrCursorInvalid)
	}
	if got := v.cursorFormat(); got != format {
		return fmt.Errorf("%w: the cursor is of format %q, not %q", ErrCursorInvalid, got, format)
	}
	return nil
}

// files keeps an adapter's files in Env.Dir.
type files struct{ dir string }

func (f files) path(name string) string { return filepath.Join(f.dir, name) }

// write replaces a file atomically: a crash leaves the old file or the new
// one, never a torn one.
func (f files) write(name string, fill func(io.Writer) error) error {
	if f.dir == "" {
		return errValidationOnly
	}
	tmp, err := os.CreateTemp(f.dir, "."+name+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := fill(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), f.path(name)); err != nil {
		return err
	}
	if d, err := os.Open(f.dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// writeJSON stores v as a file.
func (f files) writeJSON(name string, v any) error {
	return f.write(name, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		return enc.Encode(v)
	})
}

// readJSON loads a file writeJSON stored. A missing file is os.ErrNotExist.
func (f files) readJSON(name string, limit int64, v any) error {
	if f.dir == "" {
		return errValidationOnly
	}
	fh, err := os.Open(f.path(name))
	if err != nil {
		return err
	}
	defer fh.Close()
	data, err := readLimited(fh, limit)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// remove deletes a file; a missing one is fine.
func (f files) remove(name string) {
	if f.dir != "" {
		_ = os.Remove(f.path(name))
	}
}

// prune removes the files whose name starts with prefix, except keep.
func (f files) prune(prefix string, keep ...string) {
	if f.dir == "" {
		return
	}
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return
	}
	kept := map[string]bool{}
	for _, k := range keep {
		kept[k] = true
	}
	for _, e := range entries {
		if n := e.Name(); strings.HasPrefix(n, prefix) && !kept[n] {
			_ = os.Remove(f.path(n))
		}
	}
}

// pageItems splits items into pages of at most n.
func pageItems[T any](items []T, start, n int) ([]T, int, bool) {
	if start < 0 || start > len(items) {
		start = len(items)
	}
	end := start + n
	if end > len(items) {
		end = len(items)
	}
	return items[start:end], end, end < len(items)
}
