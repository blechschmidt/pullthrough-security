package intercept

import "context"

// Mode is how an intercepted request reached the proxy.
type Mode string

const (
	// ModeForward is the forward-proxy listener: the client was configured to
	// use the proxy (HTTPS_PROXY/HTTP_PROXY) and sent a CONNECT or an
	// absolute-form request for the upstream host.
	ModeForward Mode = "intercept"
	// ModeNAT is the NAT listeners: the client connected to the upstream host
	// itself, and the network (a NAT redirect, or DNS naming the proxy) sent the
	// connection here. The client is not configured for the proxy at all.
	ModeNAT Mode = "nat"
)

// RoutePrefix is the path under which an intercepted host serves the proxy's
// own links. Index documents name their packages' downloads by links to the
// backend's mount ("https://proxy/v1/pip/…"); an intercepted client is given
// the same links on the host it is talking to instead
// ("https://pypi.org/_pullthrough/v1/pip/…"), so that it never has to reach the
// proxy by a name of its own. A request under this prefix is dispatched to the
// route that follows it, on whichever intercepted host it arrives. No registry
// protocol uses the path.
const RoutePrefix = "/_pullthrough"

// Info describes an intercepted request to the handler it is dispatched to.
type Info struct {
	// Mode is how the request reached the proxy.
	Mode Mode
	// Host is the upstream host the client addressed (lowercase, no port).
	Host string
	// Origin is "scheme://host[:port]" as the client addressed it: what a link
	// in the response has to begin with to lead the client back to this host.
	Origin string
	// Backend is the name of the configured upstream the request was routed to.
	Backend string
}

type infoKey struct{}

// WithInfo returns ctx carrying info.
func WithInfo(ctx context.Context, info Info) context.Context {
	return context.WithValue(ctx, infoKey{}, info)
}

// InfoFrom returns the Info of an intercepted request. ok is false for a
// request that did not come through interception — one sent to the proxy's own
// address. Only the interception listeners attach it; nothing a client sends
// can.
func InfoFrom(ctx context.Context) (Info, bool) {
	info, ok := ctx.Value(infoKey{}).(Info)
	return info, ok
}
