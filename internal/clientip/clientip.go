// Package clientip derives the address a request really came from.
//
// The proxy attributes what it serves to a client address: the download log
// answers "which IP pulled this package", the audit log records the source of
// every decision, and anonymous traffic is scoped by address for anomaly
// detection. On a directly reachable listener that address is simply the TCP
// peer. Behind a load balancer or an ingress controller it is not — every
// connection then arrives from the balancer, and the one thing an operator
// wants to know has moved into the X-Forwarded-For header.
//
// That header is written by whoever sends the request, so it is believed only
// from peers the operator has named as trusted proxies, and then read from the
// right: each trusted hop appends the address it received the request from, so
// the right-most entry that is not itself a trusted proxy is the nearest
// address a trusted party vouches for. Everything left of it is the client's
// own claim and is ignored. With no trusted proxies configured the header is
// never read at all, which is the default.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ForwardedForHeader is the header trusted proxies append client addresses to.
const ForwardedForHeader = "X-Forwarded-For"

// maxForwardedEntries bounds how many X-Forwarded-For entries are examined. A
// legitimate chain is a handful of hops; the bound keeps a request with a
// pathological header from costing more than a constant amount of work.
const maxForwardedEntries = 64

// Info is the resolved source of one request.
type Info struct {
	// Client is the address the request is attributed to: the transport peer,
	// or — when the peer is a trusted proxy — the address that proxy forwarded
	// the request for. It is the canonical textual form of an IP address
	// whenever the peer address parses as one.
	Client string
	// Peer is the transport peer the connection actually came from.
	Peer string
	// Forwarded reports that Client was taken from a forwarding header written
	// by a trusted proxy, i.e. that Client and Peer differ by design.
	Forwarded bool
}

// Resolver resolves request sources against a fixed set of trusted proxies. The
// zero value and a nil *Resolver trust nothing and always return the transport
// peer.
type Resolver struct {
	trusted []netip.Prefix
}

// New builds a Resolver trusting the given proxies. Each entry is an IP address
// ("10.0.0.7", "fd00::7") or a CIDR prefix ("10.0.0.0/8"). An empty list is
// valid and yields a resolver that never reads a forwarding header.
func New(trustedProxies []string) (*Resolver, error) {
	prefixes, err := ParsePrefixes(trustedProxies)
	if err != nil {
		return nil, err
	}
	return &Resolver{trusted: prefixes}, nil
}

// ParsePrefixes parses a list of IP addresses and CIDR prefixes. Blank entries
// are skipped; a single address becomes a full-length prefix. Prefixes are
// normalized (masked, IPv4-mapped IPv6 unwrapped) so "::ffff:10.0.0.0/104" and
// "10.0.0.0/8" mean the same thing.
func ParsePrefixes(entries []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		prefix, err := ParsePrefix(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, prefix)
	}
	return out, nil
}

// ParsePrefix parses one IP address or CIDR prefix into a normalized prefix.
func ParsePrefix(entry string) (netip.Prefix, error) {
	entry = strings.TrimSpace(entry)
	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("clientip: %q is not a CIDR prefix: %w", entry, err)
		}
		addr := prefix.Addr()
		bits := prefix.Bits()
		if addr.Is4In6() {
			// An IPv4-mapped prefix shorter than the mapping itself (/96) would
			// cover non-IPv4 space; leave such a prefix as the IPv6 prefix it is.
			if bits >= 96 {
				addr, bits = addr.Unmap(), bits-96
			}
		}
		return netip.PrefixFrom(addr, bits).Masked(), nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("clientip: %q is not an IP address or CIDR prefix: %w", entry, err)
	}
	addr = normalize(addr)
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// TrustsAny reports whether any proxy is trusted, i.e. whether a forwarding
// header can ever be honored.
func (r *Resolver) TrustsAny() bool {
	return r != nil && len(r.trusted) > 0
}

// Trusted reports whether addr is one of the trusted proxies.
func (r *Resolver) Trusted(addr netip.Addr) bool {
	if r == nil || !addr.IsValid() {
		return false
	}
	addr = normalize(addr)
	for _, p := range r.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Resolve returns the source of req. It never fails: a peer address that is not
// an IP address (a unix socket, a test fixture) is returned verbatim, and a
// forwarding header that cannot be read is ignored.
func (r *Resolver) Resolve(req *http.Request) Info {
	if req == nil {
		return Info{}
	}
	peer, peerAddr, ok := PeerAddr(req.RemoteAddr)
	info := Info{Client: peer, Peer: peer}
	if !ok || !r.Trusted(peerAddr) {
		return info
	}
	if client, found := r.forwardedClient(req.Header.Values(ForwardedForHeader)); found {
		info.Client = client.String()
		info.Forwarded = info.Client != info.Peer
	}
	return info
}

// forwardedClient walks the X-Forwarded-For chain from the right and returns the
// first address that is not a trusted proxy. When every entry is a trusted
// proxy the left-most one is returned: the request then originated inside the
// trusted infrastructure, and that is the hop furthest from this process.
//
// The walk stops at the first entry that is not an IP address. Whatever lies to
// its left was not appended by a hop that speaks the convention, so nothing
// there is vouched for; the last trusted hop seen (if any) is the answer.
func (r *Resolver) forwardedClient(values []string) (netip.Addr, bool) {
	var entries []string
	for _, v := range values {
		entries = append(entries, strings.Split(v, ",")...)
	}
	var lastTrusted netip.Addr
	examined := 0
	for i := len(entries) - 1; i >= 0; i-- {
		entry := strings.TrimSpace(entries[i])
		if entry == "" {
			continue
		}
		examined++
		if examined > maxForwardedEntries {
			break
		}
		addr, ok := parseForwardedEntry(entry)
		if !ok {
			break
		}
		if !r.Trusted(addr) {
			return addr, true
		}
		lastTrusted = addr
	}
	if lastTrusted.IsValid() {
		return lastTrusted, true
	}
	return netip.Addr{}, false
}

// parseForwardedEntry parses one X-Forwarded-For entry. Besides a bare address
// it accepts the forms real proxies emit: "address:port" for IPv4 and
// "[address]:port" or "[address]" for IPv6.
func parseForwardedEntry(entry string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(entry); err == nil {
		return normalize(addr), true
	}
	if strings.HasPrefix(entry, "[") {
		if end := strings.IndexByte(entry, ']'); end > 0 {
			rest := entry[end+1:]
			if rest == "" || strings.HasPrefix(rest, ":") {
				if addr, err := netip.ParseAddr(entry[1:end]); err == nil {
					return normalize(addr), true
				}
			}
		}
		return netip.Addr{}, false
	}
	if host, _, err := net.SplitHostPort(entry); err == nil {
		if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
			return normalize(addr), true
		}
	}
	return netip.Addr{}, false
}

// PeerAddr splits a net/http RemoteAddr ("host:port") into its host. When the
// host is an IP address it is returned in canonical form together with the
// parsed address and ok=true; otherwise the input is returned unchanged with
// ok=false.
func PeerAddr(remoteAddr string) (host string, addr netip.Addr, ok bool) {
	host = remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return host, netip.Addr{}, false
	}
	parsed = normalize(parsed)
	return parsed.String(), parsed, true
}

// Canonical returns the canonical textual form of an IP address — IPv4-mapped
// IPv6 unwrapped, any zone dropped, IPv6 compressed — or ok=false when s is not
// an IP address. Two spellings of one address canonicalize to the same string,
// which is what makes addresses comparable as strings.
func Canonical(s string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	return normalize(addr).String(), true
}

// normalize unwraps an IPv4-mapped IPv6 address and drops the zone, so one host
// has one representation regardless of the socket family it was seen on.
func normalize(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}
