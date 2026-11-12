package proxy

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/intercept"
)

// This file is the gateway's side of TLS interception and NAT mode (Task 172):
// what it does to the responses of requests the interception listeners
// dispatched into it (see internal/intercept).
//
// Such a request was decrypted from a connection the client opened to the
// upstream host itself — pypi.org, registry.npmjs.org — and routed onto the
// backend's mount, so the backend answers it exactly as it answers a request
// sent to the proxy's own address. That includes the links the backend writes
// into an index document: they lead to its mount on the proxy's public URL
// ("https://proxy.example.com/v1/pip/files.pythonhosted.org/…"), or are
// root-relative ("/v1/pip/…") when no public URL is configured.
//
// An intercepted client cannot be sent there. It was not configured for the
// proxy — that is the point of the mode — and in NAT mode it may not even be
// able to reach the proxy's address: the network sends it the hosts it asks
// for, and nothing else. So the links to the mount in such a response are moved
// onto the host the client is talking to, under intercept.RoutePrefix:
//
//	https://proxy.example.com/v1/pip/files.pythonhosted.org/packages/…/six.whl
//	https://pypi.org/_pullthrough/v1/pip/files.pythonhosted.org/packages/…/six.whl
//
// The client follows the link to pypi.org — a host it already reaches through
// the proxy — and the interception listener dispatches the path after the
// prefix as it is. Which documents are rewritten, and where in them a link is
// recognised, are the rules of the personal-link edge (Task 177), which has the
// same problem in the other direction: personalWriter.rewritable and
// linkRewriter.

// withInterceptEdge wraps the /v1 handler chain: an intercepted request is
// served with a response writer that moves the links to the mount onto the
// intercepted host. Every other request passes through untouched.
func (g *Gateway) withInterceptEdge(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := intercept.InfoFrom(r.Context())
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		pr := &personalRequest{host: r.Host, intercept: &info}
		ctx := context.WithValue(r.Context(), personalRequestKey{}, pr)
		pw := &personalWriter{ResponseWriter: w, g: g, pr: pr, head: r.Method == http.MethodHead}
		defer pw.finish()
		next.ServeHTTP(pw, r.WithContext(ctx))
	})
}

// newInterceptRewriter returns the link rewriter for an intercepted response
// of a backend: links to the backend's mount are moved onto the intercepted
// origin, under intercept.RoutePrefix. Two kinds of link are recognised, each
// only where it starts a value (see linkRewriter.valueStarts):
//
//   - an absolute link to the proxy's public URL:
//     "<public URL>/v1/<backend>" → "<origin>/_pullthrough/v1/<backend>";
//   - a root-relative link, or one to the host the request was addressed to
//     (how the Git LFS adapter names itself):
//     "/v1/<backend>" → "/_pullthrough/v1/<backend>", which the client
//     resolves against the intercepted host it fetched the document from.
//
// The first pass runs before the second, whose output it can no longer match:
// a link the first pass wrote is preceded by the route prefix, which neither
// starts a value nor is an origin.
func newInterceptRewriter(backend, publicURL, host string, info intercept.Info) linkStream {
	mount := "/v1/" + backend
	target := intercept.RoutePrefix + mount

	var publicBase, publicPath string
	if u, err := url.Parse(strings.TrimRight(strings.TrimSpace(publicURL), "/")); err == nil && u.Host != "" {
		publicPath = strings.TrimRight(u.EscapedPath(), "/")
		publicBase = u.Scheme + "://" + u.Host + publicPath
	}

	relative := newReplacingRewriter(publicPath+mount, target, hostOrigins(host))
	if publicBase == "" {
		return relative
	}
	absolute := newReplacingRewriter(publicBase+mount, info.Origin+target, nil)
	return &chainRewriter{first: absolute, second: relative}
}

// hostOrigins are the spellings of the host a request was addressed to that
// may precede a link to it.
func hostOrigins(host string) []string {
	if host == "" {
		return nil
	}
	return []string{"https://" + host, "http://" + host}
}

// newReplacingRewriter returns a linkRewriter that replaces every occurrence of
// search that is a link — at the start of a value, optionally preceded by one
// of origins — with replacement (keeping the origin).
func newReplacingRewriter(search, replacement string, origins []string) *linkRewriter {
	rw := &linkRewriter{mount: []byte(search), replace: []byte(replacement)}
	for _, origin := range origins {
		rw.origins = append(rw.origins, []byte(origin))
		if len(origin) > rw.look {
			rw.look = len(origin)
		}
	}
	rw.look += valueStartLook
	return rw
}

// chainRewriter runs two link rewriters one after the other over a stream.
type chainRewriter struct {
	first, second *linkRewriter
}

func (c *chainRewriter) feed(chunk []byte, final bool) []byte {
	return c.second.feed(c.first.feed(chunk, final), final)
}

func (c *chainRewriter) rewriteAll(s string) string {
	return c.second.rewriteAll(c.first.rewriteAll(s))
}

func (c *chainRewriter) reset() {
	c.first.reset()
	c.second.reset()
}

func (c *chainRewriter) setMarkup(markup bool) {
	c.first.setMarkup(markup)
	c.second.setMarkup(markup)
}

func (c *chainRewriter) links() uint64 { return c.first.links() + c.second.links() }

// InterceptLinkMetrics returns what the interception edge did to the responses
// of intercepted requests (Task 172): how many it answered, in how many bodies
// it looked for links to a mount, and how many links it moved onto the
// intercepted host.
func (g *Gateway) InterceptLinkMetrics() PersonalLinkMetrics {
	return PersonalLinkMetrics{
		Requests:  g.interceptLinks.requests.Load(),
		Rewritten: g.interceptLinks.rewritten.Load(),
		Links:     g.interceptLinks.links.Load(),
	}
}
