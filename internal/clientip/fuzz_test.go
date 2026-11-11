//go:build fuzz
// +build fuzz

// Fuzz targets for the client-address resolver (Task 176).
//
// X-Forwarded-For is written by whoever sends the request. The resolver decides
// which address a download is logged under, so the properties that must hold
// for every possible header are security properties:
//
//   - a peer that is not a trusted proxy is never able to change the address
//     its request is attributed to;
//   - whatever a client puts in the header, the address the trusted proxy in
//     front of it appended is the one that is used: nothing to the left of an
//     entry a trusted party vouches for can displace it.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run='^$' -fuzz=FuzzResolve ./internal/clientip/
package clientip

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

// headerSeeds are X-Forwarded-For values: ordinary, malformed and hostile.
var headerSeeds = []string{
	"",
	"203.0.113.50",
	"10.1.1.1, 203.0.113.50",
	"203.0.113.50, 10.0.0.2",
	"unknown",
	"unknown, 203.0.113.50",
	"203.0.113.50:4711",
	"[2001:db8::1]:4711",
	"[2001:db8::1]",
	"2001:db8::1",
	"::ffff:10.0.0.9",
	"fe80::1%eth0",
	"10.0.0.2, 10.0.0.3",
	",,, ,",
	" 203.0.113.50 ",
	"203.0.113.50\r\nX-Injected: 1",
	"1.2.3.4, 5.6.7.8, 9.10.11.12, 13.14.15.16",
	strings.Repeat("1.2.3.4, ", 200) + "203.0.113.50",
	"[", "]", "[]", "[::1", "::1]", ":", "1.2.3.4:", "999.1.1.1", "1.2.3.4/8",
}

func fuzzRequest(remoteAddr string, forwarded ...string) *http.Request {
	r := &http.Request{RemoteAddr: remoteAddr, Header: http.Header{}}
	if len(forwarded) > 0 {
		r.Header[ForwardedForHeader] = forwarded
	}
	return r
}

// FuzzResolve resolves an arbitrary peer address with arbitrary forwarding
// headers. It must not panic, and its answer must stay within what the peer is
// entitled to say.
func FuzzResolve(f *testing.F) {
	peers := []string{"10.0.0.1:443", "203.0.113.9:5555", "[::1]:80", "[::ffff:10.0.0.1]:443", "@", "", "not an address", "10.0.0.1"}
	for _, peer := range peers {
		for _, h := range headerSeeds {
			f.Add(peer, h, "")
		}
	}
	f.Add("10.0.0.1:443", "10.1.1.1", "203.0.113.50")

	trusting, err := New([]string{"10.0.0.0/8", "fd00::/8", "192.168.1.10"})
	if err != nil {
		f.Fatal(err)
	}
	trustingNone, err := New(nil)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, remoteAddr, first, second string) {
		headers := []string{first}
		if second != "" {
			headers = append(headers, second)
		}
		req := fuzzRequest(remoteAddr, headers...)

		// With no trusted proxies — the default — the header does not exist.
		for name, r := range map[string]*Resolver{"nil": nil, "empty": trustingNone} {
			got := r.Resolve(req)
			if got.Forwarded || got.Client != got.Peer {
				t.Fatalf("%s resolver, peer %q, header %q: got %+v; the header must be ignored", name, remoteAddr, headers, got)
			}
		}

		got := trusting.Resolve(req)
		host, addr, isIP := PeerAddr(remoteAddr)
		if got.Peer != host {
			t.Fatalf("Peer = %q, want the transport peer %q", got.Peer, host)
		}
		if !isIP || !trusting.Trusted(addr) {
			// The peer is not one of the operator's proxies: nothing it sends can
			// move the address.
			if got.Forwarded || got.Client != host {
				t.Fatalf("untrusted peer %q with header %q is attributed to %q", remoteAddr, headers, got.Client)
			}
			return
		}
		if !got.Forwarded {
			if got.Client != host {
				t.Fatalf("not forwarded, yet Client %q differs from the peer %q", got.Client, host)
			}
			return
		}
		// Forwarded: the client is an address, in canonical form, other than the
		// peer, and it is one the header actually names.
		canonical, ok := Canonical(got.Client)
		if !ok || canonical != got.Client {
			t.Fatalf("forwarded Client %q is not a canonical IP address", got.Client)
		}
		if got.Client == got.Peer {
			t.Fatalf("Forwarded is set although Client equals the peer %q", got.Peer)
		}
		if !headerNames(headers, got.Client) {
			t.Fatalf("Client %q does not appear in the header %q", got.Client, headers)
		}
	})
}

// headerNames reports whether some entry of the header values is addr.
func headerNames(values []string, addr string) bool {
	for _, v := range values {
		for _, entry := range strings.Split(v, ",") {
			if parsed, ok := parseForwardedEntry(strings.TrimSpace(entry)); ok && parsed.String() == addr {
				return true
			}
		}
	}
	return false
}

// FuzzForgedPrefixCannotMoveTheClient is the property the trust model exists
// for. A client behind a trusted proxy sends any X-Forwarded-For it likes; the
// proxy appends the address it saw the client at. Whatever the client sent —
// forged addresses, trusted-proxy addresses, garbage, a thousand entries — the
// request is attributed to the address the proxy appended.
func FuzzForgedPrefixCannotMoveTheClient(f *testing.F) {
	for _, h := range headerSeeds {
		f.Add(h, uint8(0))
		f.Add(h, uint8(1))
		f.Add(h, uint8(2))
	}
	resolver, err := New([]string{"10.0.0.0/8", "fd00::/8"})
	if err != nil {
		f.Fatal(err)
	}
	const (
		proxy  = "10.0.0.1:443" // the trusted proxy the connection comes from
		client = "203.0.113.50" // where that proxy saw the client
		inner  = "10.0.0.2"     // a second trusted hop
	)
	want := netip.MustParseAddr(client).String()

	f.Fuzz(func(t *testing.T, forged string, shape uint8) {
		var headers []string
		switch shape % 3 {
		case 0: // the proxy appended to the client's header line
			headers = []string{forged + ", " + client}
		case 1: // the proxy added a header line of its own after the client's
			headers = []string{forged, client}
		default: // two trusted hops: the outer saw the client, the inner the outer
			headers = []string{forged + ", " + client + ", " + inner}
		}
		got := resolver.Resolve(fuzzRequest(proxy, headers...))
		if got.Client != want || !got.Forwarded {
			t.Fatalf("header %q: attributed to %q (forwarded=%v), want %q — a forged prefix moved the client",
				headers, got.Client, got.Forwarded, want)
		}
		if got.Peer != "10.0.0.1" {
			t.Fatalf("Peer = %q, want the proxy the connection came from", got.Peer)
		}
	})
}
