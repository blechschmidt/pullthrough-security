package proxy

import (
	"bytes"
	"context"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/intercept"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks"
)

// This file is the gateway's side of personal cache links (internal/userlinks,
// Task 177): a user's own address for every package source the proxy serves,
//
//	/v1/npm/lodash                       the mount
//	/u/ptl1…/v1/npm/lodash               the same resource, as alice
//
// so that what is downloaded through it is recorded under the user's name.
//
// The personal prefix is an edge concern, and deliberately stays one. It is
// taken off the path before anything else looks at the request — the tracing
// span, the access-control check, the backend, the cache, the audit trail and
// the download log all see "/v1/npm/lodash" — and it is put back into the
// response on the way out. Nothing behind the edge ever holds the token, so
// nothing behind the edge can log it, cache it or send it upstream; and what a
// backend caches is the same bytes whoever asked.
//
// Putting it back is the part that needs care. An index document tells the
// client where to fetch the package from, and the protocol adapters write that
// as a link to the mount ("https://proxy/v1/npm/lodash/-/lodash-4.17.21.tgz").
// A client that followed it would leave its personal address at the first
// download — the one request the link exists to attribute. So the links to the
// mount in such a document are rewritten to the personal form (linkRewriter).

// personalRequest is what the edge knows about a request that came in through a
// personal link, shared with the handler chain behind it.
type personalRequest struct {
	// prefix is the personal prefix as the client sent it: "/u/<token>".
	prefix string
	// host is the Host the request was addressed to.
	host string
	// intercept is set for a request that came through TLS interception or NAT
	// (Task 172) rather than a personal link: its links are moved onto the
	// upstream host the client is talking to, not given a personal prefix (see
	// interceptedge.go).
	intercept *intercept.Info

	// backend and class are filled in by handleBackend as the request is routed
	// and resolved. They are written by the goroutine serving the request,
	// before it writes the response, and read by the response writer on that
	// same goroutine.
	backend  string
	resolved bool
	class    backends.ArtifactClass
}

type personalRequestKey struct{}

// personalFrom returns the request's personalRequest, or nil for a request that
// did not come in through a personal link.
func personalFrom(ctx context.Context) *personalRequest {
	pr, _ := ctx.Value(personalRequestKey{}).(*personalRequest)
	return pr
}

// notePersonalBackend records which backend serves a personal request.
func notePersonalBackend(ctx context.Context, name string) {
	if pr := personalFrom(ctx); pr != nil {
		pr.backend = name
	}
}

// notePersonalResolved records what a personal request resolved to.
func notePersonalResolved(ctx context.Context, resolved *backends.Resolved) {
	if pr := personalFrom(ctx); pr != nil && resolved != nil {
		pr.resolved = true
		pr.class = resolved.Artifact.Class
	}
}

// splitPersonalPath splits "<prefix>/<token>/<rest>" into the token and
// "/<rest>". prefix is "/u".
func splitPersonalPath(p, prefix string) (token, rest string, ok bool) {
	after, found := strings.CutPrefix(p, prefix+"/")
	if !found {
		return "", "", false
	}
	token, rest, _ = strings.Cut(after, "/")
	if token == "" {
		return "", "", false
	}
	return token, "/" + rest, true
}

// redactedLink stands in for a link's token wherever a personal path is
// written down.
const redactedLink = "<link>"

// redactPersonalPath returns p with the token of a personal link replaced by a
// placeholder: "/u/<link>/v1/npm/lodash". It is what the request log shows.
// The component after the personal prefix is a token wherever the prefix
// starts the path, whatever it looks like; any other component that starts
// like a token ("ptl1…") is taken for one as well — the leading components of
// a container repository ("/v2/u/<token>/…"), a second link in one path, a
// link pasted somewhere it does not belong.
func redactPersonalPath(p, prefix string) string {
	if prefix == "" {
		return p
	}
	if _, rest, ok := splitPersonalPath(p, prefix); ok {
		return prefix + "/" + redactedLink + redactTokenComponents(rest)
	}
	return redactTokenComponents(p)
}

// redactTokenComponents replaces every path component that starts like a link
// token.
func redactTokenComponents(p string) string {
	if !strings.Contains(p, userlinks.TokenPrefix) {
		return p
	}
	parts := strings.Split(p, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, userlinks.TokenPrefix) {
			parts[i] = redactedLink
		}
	}
	return strings.Join(parts, "/")
}

// handlePersonalPath serves "<prefix>/<token>/…": it takes the personal prefix
// off the path, remembers the token for the access-control check, and hands the
// request to the handler chain that serves the same path without the prefix —
// next for "/v1/…", registry for the container registry alias "/v2/…" — with a
// response writer that puts the prefix back into the links of the response.
//
// Only package sources are served under a personal prefix. The admin surface,
// the metrics and the self-service page are not: a link identifies a user to
// the cache, it is not a login.
func (g *Gateway) handlePersonalPath(next, registry http.Handler) http.Handler {
	prefix := g.deps.UserLinks.PathPrefix()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, rest, ok := splitPersonalPath(r.URL.Path, prefix)
		var target http.Handler
		switch {
		case !ok:
		case strings.HasPrefix(rest, "/v1/"):
			target = next
		case registry != nil && (rest == "/v2" || strings.HasPrefix(rest, registryRootPrefix)):
			target = registry
		}
		if target == nil {
			http.Error(w, "not found: a personal cache link has the form "+prefix+"/<link>/v1/<upstream>/…",
				http.StatusNotFound)
			return
		}

		pr := &personalRequest{prefix: prefix + "/" + token, host: r.Host}
		ctx := context.WithValue(r.Context(), personalRequestKey{}, pr)
		ctx = userlinks.WithPathToken(ctx, token)

		// Rewrite on a copy: the request the outer middleware holds keeps the
		// path the client sent (which the request log redacts).
		r2 := r.Clone(ctx)
		r2.URL.Path = rest
		// The prefix consists of characters that are never escaped, so it has
		// the same spelling in the raw path — unless the client escaped it
		// needlessly, in which case the raw path is dropped and derived anew.
		if raw, ok := strings.CutPrefix(r.URL.RawPath, pr.prefix); ok && raw != "" {
			r2.URL.RawPath = raw
		} else {
			r2.URL.RawPath = ""
		}
		r2.RequestURI = r2.URL.RequestURI()

		pw := &personalWriter{ResponseWriter: w, g: g, pr: pr, head: r.Method == http.MethodHead}
		defer pw.finish()
		target.ServeHTTP(pw, r2)
	})
}

// registryPersonalPath recognises a personal link in the path of a request to
// the container registry alias, where it takes the form the clients can
// express: the leading components of the repository,
//
//	docker pull proxy.example.com/u/<token>/dockerhub/library/alpine
//	→ GET /v2/u/<token>/dockerhub/library/alpine/manifests/latest
//
// It returns the token and the path without it. Only a component that starts
// like a link token counts — "ptl1…" — because "u" is also a perfectly good
// name for a repository namespace, and a request for such a repository must
// keep meaning what it meant. A component that starts like a token and is not
// one (cut short, mistyped) is returned all the same: it is refused as a link
// that is not good, and not passed on as a repository name — which would send
// most of a user's link upstream and into the records of the request.
func (g *Gateway) registryPersonalPath(p string) (token, rest string, ok bool) {
	links := g.deps.UserLinks
	if !links.Enabled() {
		return "", "", false
	}
	after, found := strings.CutPrefix(p, "/v2")
	if !found {
		return "", "", false
	}
	token, rest, ok = splitPersonalPath(after, links.PathPrefix())
	if !ok || !strings.HasPrefix(token, userlinks.TokenPrefix) {
		return "", "", false
	}
	return token, "/v2" + rest, true
}

// checkAccess decides whether a backend request is admitted, and as whom.
//
// A request that carries a personal link — in its path, or as a credential — is
// identified by it: the link's user is then authorized and metered exactly as a
// caller authenticated by a token is. This holds with client authentication
// switched off as well; the identity is then for the record only. A link that
// cannot be honoured refuses the request outright. It never falls back to
// anonymous access: the user believes the download is recorded under their
// name, and a revoked link that went on working would not be revoked.
//
// Every other request goes through the enforcer as before.
func (g *Gateway) checkAccess(ctx context.Context, r *http.Request, name, ecosystem string) auth.Result {
	if links := g.deps.UserLinks; links.Enabled() {
		p, err := links.Authenticate(ctx, r)
		var linkErr *userlinks.AuthError
		switch {
		case err == nil:
			return g.deps.Enforcer.Admit(p, name, ecosystem)
		case errors.As(err, &linkErr):
			res := auth.Result{Allowed: false, Status: linkErr.Status(), Reason: linkErr.Error(), Stage: auth.StageAuthn}
			if linkErr.Link != nil {
				// An expired or revoked link is still a known one, and the record
				// of the refusal should say whose it was.
				res.Principal = &auth.Principal{
					Subject:    linkErr.Link.Subject,
					Team:       linkErr.Link.Team,
					Method:     userlinks.MethodPersonalLink,
					Attributes: map[string]string{userlinks.AttrLink: linkErr.Link.ID, userlinks.AttrVia: linkErr.Via},
				}
			}
			return res
		}
	}
	return g.deps.Enforcer.Check(ctx, r, name, ecosystem)
}

// personalLinkID returns the identifier of the personal link a principal was
// identified by, or "".
func personalLinkID(p *auth.Principal) string {
	if p == nil || p.Method != userlinks.MethodPersonalLink {
		return ""
	}
	return p.Attributes[userlinks.AttrLink]
}

// --- putting the prefix back --------------------------------------------------

// personalStats counts what the edge did to responses of personal requests.
type personalStats struct {
	requests  atomic.Uint64 // responses to requests that came in through a personal path
	rewritten atomic.Uint64 // responses whose body was searched for links to rewrite
	links     atomic.Uint64 // links rewritten
}

// PersonalLinkMetrics is a snapshot of the edge's personal-link counters.
type PersonalLinkMetrics struct {
	// Requests is the number of responses to requests that came in through a
	// personal path.
	Requests uint64
	// Rewritten is the number of responses whose body was searched for links to
	// the mount; Links the number of links that were given the personal prefix.
	Rewritten uint64
	Links     uint64
}

// PersonalLinkMetrics returns the edge's personal-link counters.
func (g *Gateway) PersonalLinkMetrics() PersonalLinkMetrics {
	return PersonalLinkMetrics{
		Requests:  g.personal.requests.Load(),
		Rewritten: g.personal.rewritten.Load(),
		Links:     g.personal.links.Load(),
	}
}

// linkHeaders are the response headers that can carry a link to the mount: the
// target of a redirect a backend relays, and Terraform's module download
// location.
var linkHeaders = [...]string{"Location", "Content-Location", "X-Terraform-Get"}

// personalWriter is the response writer of a personal request. It forwards the
// response unchanged except for three things:
//
//   - links to the mount in the headers above get the personal prefix;
//   - the response is marked private: it was produced for one user, and a
//     shared cache between the proxy and its clients must not hand it to
//     another;
//   - the body of an index document gets the personal prefix on its links to
//     the mount (see rewritable for which bodies qualify).
//
// It holds the response's status line back until the first byte of the body is
// there, because whether the body is rewritten — and therefore whether a
// Content-Length can be promised — is decided with that byte in hand.
type personalWriter struct {
	http.ResponseWriter
	g  *Gateway
	pr *personalRequest
	// head reports a HEAD request: there will be no body to decide by.
	head bool

	status      int
	wroteHeader bool // the handler has set the final status
	sent        bool // the status line has been forwarded
	rewriter    linkStream
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *personalWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *personalWriter) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		// An informational response is not the answer; pass it on as it is.
		w.ResponseWriter.WriteHeader(code)
		return
	}
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = code
}

func (w *personalWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if !w.sent {
		w.send(p)
	}
	if w.rewriter == nil {
		return w.ResponseWriter.Write(p)
	}
	if out := w.rewriter.feed(p, false); len(out) > 0 {
		if _, err := w.ResponseWriter.Write(out); err != nil {
			return 0, err
		}
	}
	// The caller's bytes were all taken, whatever number of bytes that became.
	return len(p), nil
}

// Flush forwards what can be forwarded. The few bytes a rewriter holds back —
// the possible beginning of a link — stay held: they cannot be judged yet.
func (w *personalWriter) Flush() {
	if w.wroteHeader && !w.sent {
		w.send(nil)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// send forwards the status line, having prepared the headers and decided what
// happens to the body. first is the first chunk of the body, or nil when there
// is none yet (a flush before any byte, a response without a body).
func (w *personalWriter) send(first []byte) {
	w.sent = true
	h := w.Header()
	var rw linkStream
	if w.pr.intercept != nil {
		w.g.interceptLinks.requests.Add(1)
		if w.pr.backend != "" && w.g.opts.LinkBackends[w.pr.backend] {
			rw = newInterceptRewriter(w.pr.backend, w.g.opts.PublicURL, w.pr.host, *w.pr.intercept)
		}
	} else {
		w.g.personal.requests.Add(1)
		if w.pr.backend != "" && w.g.opts.LinkBackends[w.pr.backend] {
			rw = newLinkRewriter("/v1/"+w.pr.backend, w.pr.prefix, w.g.opts.PublicURL, w.pr.host)
		}
		makePrivate(h)
		h.Set("Referrer-Policy", "no-referrer")
	}
	if rw != nil {
		for _, name := range linkHeaders {
			if v := h.Get(name); v != "" {
				if out := rw.rewriteAll(v); out != v {
					h.Set(name, out)
				}
			}
		}
	}

	if rw != nil && w.rewritable(h, first) {
		// The rewritten body is longer than the original by an amount not known
		// until it has been read; the response is sent without a length.
		h.Del("Content-Length")
		h.Del("Accept-Ranges")
		if !w.head {
			rw.reset()
			rw.setMarkup(isMarkup(h.Get("Content-Type")))
			w.rewriter = rw
			if w.pr.intercept != nil {
				w.g.interceptLinks.rewritten.Add(1)
			} else {
				w.g.personal.rewritten.Add(1)
			}
		}
	}
	w.ResponseWriter.WriteHeader(w.status)
}

// rewritable reports whether the body of the response is one whose links to
// the mount are rewritten: an index document a protocol adapter wrote links
// into. Everything that is, or could be, content a client verifies against a
// digest it obtained elsewhere is left byte for byte as it is.
//
//   - Only a complete, successful response: not a range, not an error.
//   - Never an installable artifact (a payload), and never anything that came
//     out of the content cache — what is cached is immutable content.
//   - Only text. The answer is taken from the media type and, for a type that
//     says nothing ("application/octet-stream", as static hosts label an
//     index.yaml), from the first bytes.
//   - Not a compressed body: there is nothing to find in one.
//
// That the backend is one whose adapter writes links to its mount at all was
// established by the caller.
func (w *personalWriter) rewritable(h http.Header, first []byte) bool {
	if w.status != http.StatusOK || h.Get("Content-Range") != "" {
		return false
	}
	if w.pr.resolved && w.pr.class == backends.ArtifactPayload {
		return false
	}
	if cache := h.Get("X-Cache"); cache != "" && cache != "BYPASS" {
		return false
	}
	if enc := strings.TrimSpace(h.Get("Content-Encoding")); enc != "" && !strings.EqualFold(enc, "identity") {
		return false
	}
	switch textualType(h.Get("Content-Type")) {
	case typeText:
		return true
	case typeUnknown:
		if first == nil {
			// Nothing to look at. A HEAD is not rewritten in any case: its
			// headers are those of the content (a length, ranges). A GET that
			// flushed before its first byte is taken for text.
			return !w.head
		}
		return looksLikeText(first)
	default:
		return false
	}
}

// finish forwards what the response still holds back: the status line of a
// response without a body, and the tail a rewriter kept.
func (w *personalWriter) finish() {
	if !w.wroteHeader {
		// The handler answered nothing. That is its business — and the server's,
		// which then answers for it; inventing a status here would hide it.
		return
	}
	if !w.sent {
		w.send(nil)
	}
	if w.rewriter != nil {
		if out := w.rewriter.feed(nil, true); len(out) > 0 {
			_, _ = w.ResponseWriter.Write(out)
		}
		if w.pr.intercept != nil {
			w.g.interceptLinks.links.Add(w.rewriter.links())
		} else {
			w.g.personal.links.Add(w.rewriter.links())
		}
	}
}

// makePrivate marks a response as produced for one user. An upstream's
// "public" is replaced; its lifetime directives are kept.
func makePrivate(h http.Header) {
	var kept []string
	for _, line := range h.Values("Cache-Control") {
		for _, directive := range strings.Split(line, ",") {
			directive = strings.TrimSpace(directive)
			name, _, _ := strings.Cut(directive, "=")
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "", "public", "private", "s-maxage":
				continue
			}
			kept = append(kept, directive)
		}
	}
	h.Set("Cache-Control", strings.Join(append([]string{"private"}, kept...), ", "))
}

// Kinds of media type, for the question "is this text".
const (
	typeBinary = iota
	typeText
	typeUnknown
)

// textualType classifies a Content-Type.
func textualType(contentType string) int {
	if strings.TrimSpace(contentType) == "" {
		return typeUnknown
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return typeBinary
	}
	switch {
	case strings.HasPrefix(mt, "text/"),
		strings.HasSuffix(mt, "+json"), strings.HasSuffix(mt, "+xml"), strings.HasSuffix(mt, "+yaml"):
		return typeText
	}
	switch mt {
	case "application/json", "application/xml", "application/yaml", "application/x-yaml",
		"application/toml", "application/x-ndjson", "application/javascript":
		return typeText
	case "application/octet-stream", "binary/octet-stream":
		return typeUnknown
	}
	return typeBinary
}

// looksLikeText reports whether the beginning of a body reads as text: valid
// UTF-8 without NUL bytes. A multi-byte character cut off by the end of the
// sample does not count against it.
func looksLikeText(sample []byte) bool {
	if len(sample) > 1024 {
		sample = sample[:1024]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return false
	}
	for trimmed := 0; trimmed < utf8.UTFMax && len(sample) > 0; trimmed++ {
		if utf8.Valid(sample) {
			return true
		}
		sample = sample[:len(sample)-1]
	}
	return utf8.Valid(sample)
}

// linkRewriter gives the links to one mount of the proxy, in a stream of text,
// their personal prefix:
//
//	https://proxy.example.com/v1/npm/lodash/-/lodash-4.17.21.tgz
//	https://proxy.example.com/u/ptl1…/v1/npm/lodash/-/lodash-4.17.21.tgz
//
// It looks for the mount path ("/v1/npm") and inserts the prefix in front of
// it — but only where the text really is a link to this proxy's mount, which is
// decided by what stands on either side:
//
//   - After it: the end of the path component — a slash, a quote, the end of the
//     text. "/v1/npm-internal" is another mount.
//   - Before it: the proxy's own address — its public URL, or the scheme and
//     host the request was addressed to (how the Git LFS adapter names itself) —
//     or nothing, for a root-relative link. "https://example.org/v1/npm/" in a
//     package's README is someone else's URL and stays that.
//   - Before that: the start of a value. The link must be the beginning of the
//     value it is written in (see valueStarts) — never text in the middle of
//     one. A document an adapter serves carries text its package's author
//     wrote: a dependency given as "https://attacker.example/x?a=/v1/npm/", a
//     homepage, a description. Rewriting a mount path inside such a value would
//     put the user's link into a URL that leads elsewhere — and npm fetches
//     URL dependencies by itself. A link the proxy wrote is always a whole
//     value, so it is not missed by this; "see /v1/npm" in prose is not
//     rewritten either.
//
// It works on a stream: feed takes the next chunk and returns what can be
// emitted, holding back the few trailing bytes that might be the beginning of
// a link that continues in the next chunk.
type linkRewriter struct {
	mount  []byte // "/v1/npm"
	prefix []byte // "/u/<token>"
	// replace, when set, is written in place of a match instead of
	// prefix+mount: the whole matched text is replaced (see
	// newInterceptRewriter).
	replace []byte
	// markup allows the value openers of HTML and XML besides the JSON one: an
	// attribute value in single quotes. It is set for a body of such a media
	// type; in JSON a single quote is an ordinary character of a string.
	markup bool
	// path is the path component of the proxy's public URL (usually empty):
	// with a public URL of https://example.com/proxy, the mount is linked to as
	// "/proxy/v1/npm".
	path []byte
	// origins are the spellings of "this proxy" that may precede path+mount.
	origins [][]byte
	// look is how many bytes before a match have to be seen to judge it.
	look int

	// held is input not yet emitted: the possible beginning of a match.
	held []byte
	// behind is the tail of the input already emitted, for looking back.
	behind []byte
	// started reports that some input has been consumed.
	started bool
	// emitted counts the bytes of input consumed so far. While it is no more
	// than len(behind), behind is the whole text before the current chunk.
	emitted int
	// count is the number of links rewritten.
	count uint64
}

func newLinkRewriter(mount, prefix, publicURL, host string) *linkRewriter {
	rw := &linkRewriter{mount: []byte(mount), prefix: []byte(prefix)}
	addOrigin := func(origin string) {
		for _, known := range rw.origins {
			if string(known) == origin {
				return
			}
		}
		rw.origins = append(rw.origins, []byte(origin))
	}
	if u, err := url.Parse(strings.TrimRight(strings.TrimSpace(publicURL), "/")); err == nil && u.Host != "" {
		rw.path = []byte(strings.TrimRight(u.EscapedPath(), "/"))
		addOrigin(u.Scheme + "://" + u.Host)
	}
	if host != "" {
		addOrigin("https://" + host)
		addOrigin("http://" + host)
	}
	for _, origin := range rw.origins {
		if n := len(origin) + len(rw.path); n > rw.look {
			rw.look = n
		}
	}
	if n := len(rw.path); n > rw.look {
		rw.look = n
	}
	// And what decides whether a value starts there: an opening quote with the
	// backslashes that may escape it, or a line's indentation and "- ".
	rw.look += valueStartLook
	return rw
}

// linkStream is a streaming link rewriter: a linkRewriter, or a chain of them.
type linkStream interface {
	// feed consumes the next chunk and returns the output that is ready; final
	// marks the end of the stream.
	feed(chunk []byte, final bool) []byte
	// rewriteAll rewrites a complete text, such as a header value.
	rewriteAll(s string) string
	// reset forgets a stream.
	reset()
	// setMarkup says whether the text is HTML/XML (see linkRewriter.markup).
	setMarkup(markup bool)
	// links is the number of links rewritten.
	links() uint64
}

func (rw *linkRewriter) setMarkup(markup bool) { rw.markup = markup }
func (rw *linkRewriter) links() uint64         { return rw.count }

// valueStartLook is how far before a link valueStarts looks back.
const valueStartLook = 64

// reset forgets a stream, so the rewriter can be used for another.
func (rw *linkRewriter) reset() {
	rw.held, rw.behind, rw.started, rw.emitted, rw.count = nil, nil, false, 0, 0
}

// rewriteAll rewrites a complete text, such as a header value.
func (rw *linkRewriter) rewriteAll(s string) string {
	rw.reset()
	out := rw.feed([]byte(s), true)
	rw.reset()
	return string(out)
}

// feed consumes the next chunk of the stream and returns the output that is
// ready. final marks the end of the stream: nothing is held back.
func (rw *linkRewriter) feed(chunk []byte, final bool) []byte {
	buf := chunk
	if len(rw.held) > 0 {
		buf = append(rw.held, chunk...)
		rw.held = nil
	}
	if len(buf) == 0 {
		return nil
	}

	out := make([]byte, 0, len(buf)+len(rw.prefix))
	done := 0 // buf[:done] has been emitted
	for {
		i := bytes.Index(buf[done:], rw.mount)
		if i < 0 {
			break
		}
		i += done
		end := i + len(rw.mount)
		if end == len(buf) && !final {
			// The mount path ends the chunk; what follows it decides whether it
			// is one. Wait for it.
			break
		}
		if (end == len(buf) || mountEnds(buf[end])) && rw.linkStartsAt(buf, i) {
			out = append(out, buf[done:i]...)
			if rw.replace != nil {
				out = append(out, rw.replace...)
			} else {
				out = append(out, rw.prefix...)
				out = append(out, rw.mount...)
			}
			done = end
			rw.count++
			continue
		}
		// Not a link to this mount. Step past its first byte and go on looking.
		out = append(out, buf[done:i+1]...)
		done = i + 1
	}

	// Hold back the end of the buffer for as far as it could be the beginning
	// of the mount path: a prefix of it, or all of it without what follows.
	hold := 0
	if !final {
		rest := buf[done:]
		for n := min(len(rw.mount), len(rest)); n > 0; n-- {
			if bytes.Equal(rest[len(rest)-n:], rw.mount[:n]) {
				hold = n
				break
			}
		}
	}
	emitTo := len(buf) - hold
	out = append(out, buf[done:emitTo]...)

	// Remember the tail of what has been consumed, for looking back from the
	// start of the next chunk.
	if rw.look > 0 {
		tail := append(rw.behind, buf[:emitTo]...)
		if len(tail) > rw.look {
			tail = tail[len(tail)-rw.look:]
		}
		rw.behind = append([]byte(nil), tail...)
	}
	rw.started = rw.started || emitTo > 0
	rw.emitted += emitTo
	if hold > 0 {
		rw.held = append([]byte(nil), buf[emitTo:]...)
	}
	return out
}

// linkStartsAt reports whether the mount path found at buf[i] is the path of a
// link to this proxy: preceded by the proxy's public path, then by its origin
// or nothing (a root-relative link), and that at the start of a value.
func (rw *linkRewriter) linkStartsAt(buf []byte, i int) bool {
	// The text before the match, as far back as is needed: the tail of what
	// earlier chunks held, then this chunk up to the match. complete reports
	// that this is everything that came before.
	before := buf[:i]
	complete := !rw.started
	if len(before) < rw.look && len(rw.behind) > 0 {
		before = append(append(make([]byte, 0, len(rw.behind)+i), rw.behind...), buf[:i]...)
		complete = rw.emitted <= len(rw.behind)
	}
	if !bytes.HasSuffix(before, rw.path) {
		return false
	}
	before = before[:len(before)-len(rw.path)]
	for _, origin := range rw.origins {
		if bytes.HasSuffix(before, origin) {
			return rw.valueStarts(before[:len(before)-len(origin)], complete)
		}
	}
	return rw.valueStarts(before, complete)
}

// valueStarts reports whether a value starts after before — the text that
// precedes a link candidate; complete says whether it is all the text there
// was. A value starts:
//
//   - at the beginning of the text: a header value, a document that is a link;
//   - after a double quote that is not escaped: the opening quote of a JSON
//     string, or of an attribute value. (In JSON an unescaped quote followed by
//     a link can only open a string; one inside a string is written \".)
//   - in HTML and XML, after the single quote of an attribute value: ='…';
//   - after a YAML sequence indicator at the beginning of a line: "  - ";
//   - after a field name at the beginning of a line: "URL: " in a Nix narinfo,
//     "home: " in YAML. (A field name is letters, digits, "-", "_" and ".";
//     "x: " in the middle of a line, as in a value of someone else's, is not
//     one.)
//
// Whatever cannot be decided within the text at hand — a long run of
// backslashes, a deep indentation — is not a value start: a link missed costs
// an attribution; a link added where it does not belong could cost the link.
func (rw *linkRewriter) valueStarts(before []byte, complete bool) bool {
	n := len(before)
	if n == 0 {
		return complete
	}
	switch before[n-1] {
	case '"':
		// Escaped when an odd number of backslashes precedes it.
		k := n - 2
		for k >= 0 && before[k] == '\\' {
			k--
		}
		if k < 0 && !complete {
			return false // the backslashes run past what is known
		}
		return (n-2-k)%2 == 0
	case '\'':
		if !rw.markup {
			return false
		}
		k := n - 2
		for k >= 0 && (before[k] == ' ' || before[k] == '\t') {
			k--
		}
		return k >= 0 && before[k] == '='
	case ' ':
		switch {
		case n >= 2 && before[n-2] == '-':
			// "- " after the indentation that starts a line.
			return startsLine(before, n-3, complete)
		case n >= 2 && before[n-2] == ':':
			// "<field>: " at the start of a line.
			k := n - 3
			for k >= 0 && isFieldChar(before[k]) {
				k--
			}
			if k == n-3 {
				return false // no field name
			}
			return startsLine(before, k, complete)
		}
	}
	return false
}

// startsLine reports whether before[:k+1] ends with the indentation at the
// start of a line: blanks back to a line break, or to the beginning of the
// text.
func startsLine(before []byte, k int, complete bool) bool {
	for k >= 0 && (before[k] == ' ' || before[k] == '\t') {
		k--
	}
	if k < 0 {
		return complete
	}
	return before[k] == '\n' || before[k] == '\r'
}

// isFieldChar reports whether c can be part of a field name ("URL",
// "file_uri", "x.y-z").
func isFieldChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
}

// mountEnds reports whether c, following the mount path, ends its last path
// component — so that the text is this mount and not one whose name merely
// starts the same way.
func mountEnds(c byte) bool {
	switch c {
	case '/', '"', '\'', '?', '#', '<', '>', ')', ']', '}', ',', ';', '\\', '&', ' ', '\t', '\r', '\n':
		return true
	}
	return false
}

// isMarkup reports whether a Content-Type is HTML or XML, whose attribute
// values may be written in single quotes.
func isMarkup(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mt == "text/html" || mt == "application/xhtml+xml" || mt == "text/xml" ||
		mt == "application/xml" || strings.HasSuffix(mt, "+xml")
}
