package clientip

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func request(remoteAddr string, forwardedFor ...string) *http.Request {
	r := &http.Request{RemoteAddr: remoteAddr, Header: http.Header{}}
	for _, v := range forwardedFor {
		r.Header.Add(ForwardedForHeader, v)
	}
	return r
}

func mustNew(t *testing.T, trusted ...string) *Resolver {
	t.Helper()
	r, err := New(trusted)
	if err != nil {
		t.Fatalf("New(%v): %v", trusted, err)
	}
	return r
}

// With no trusted proxies the header is a client-controlled string and must
// never be read: anyone could otherwise attribute their downloads to an address
// of their choosing.
func TestUntrustedPeerHeaderIsIgnored(t *testing.T) {
	for name, r := range map[string]*Resolver{
		"nil resolver":      nil,
		"zero resolver":     {},
		"no proxies":        mustNew(t),
		"other proxy range": mustNew(t, "10.0.0.0/8"),
	} {
		t.Run(name, func(t *testing.T) {
			got := r.Resolve(request("203.0.113.9:4711", "198.51.100.1"))
			want := Info{Client: "203.0.113.9", Peer: "203.0.113.9"}
			if got != want {
				t.Fatalf("Resolve = %+v, want %+v", got, want)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	r := mustNew(t, "10.0.0.0/8", "192.168.7.7", "fd00::/8")

	tests := []struct {
		name string
		req  *http.Request
		want Info
	}{
		{
			name: "direct client, no header",
			req:  request("203.0.113.9:4711"),
			want: Info{Client: "203.0.113.9", Peer: "203.0.113.9"},
		},
		{
			name: "trusted proxy, single hop",
			req:  request("10.1.2.3:80", "203.0.113.9"),
			want: Info{Client: "203.0.113.9", Peer: "10.1.2.3", Forwarded: true},
		},
		{
			name: "trusted proxy without a header is its own client",
			req:  request("10.1.2.3:80"),
			want: Info{Client: "10.1.2.3", Peer: "10.1.2.3"},
		},
		{
			// The client wrote the left entries itself; only the entry the trusted
			// proxy appended counts.
			name: "spoofed prefix is ignored",
			req:  request("10.1.2.3:80", "1.1.1.1, 8.8.8.8, 203.0.113.9"),
			want: Info{Client: "203.0.113.9", Peer: "10.1.2.3", Forwarded: true},
		},
		{
			name: "chain of trusted proxies is skipped from the right",
			req:  request("10.1.2.3:80", "198.51.100.4, 192.168.7.7, 10.9.9.9"),
			want: Info{Client: "198.51.100.4", Peer: "10.1.2.3", Forwarded: true},
		},
		{
			name: "header split across lines is one chain",
			req:  request("10.1.2.3:80", "1.1.1.1", "198.51.100.4", "10.9.9.9"),
			want: Info{Client: "198.51.100.4", Peer: "10.1.2.3", Forwarded: true},
		},
		{
			name: "all hops trusted: the furthest one",
			req:  request("10.1.2.3:80", "10.5.5.5, 192.168.7.7"),
			want: Info{Client: "10.5.5.5", Peer: "10.1.2.3", Forwarded: true},
		},
		{
			name: "the proxy forwarding for itself is not 'forwarded'",
			req:  request("10.1.2.3:80", "10.1.2.3"),
			want: Info{Client: "10.1.2.3", Peer: "10.1.2.3"},
		},
		{
			name: "garbage right-most entry: nothing is vouched for",
			req:  request("10.1.2.3:80", "203.0.113.9, unknown"),
			want: Info{Client: "10.1.2.3", Peer: "10.1.2.3"},
		},
		{
			name: "garbage behind a trusted hop: the trusted hop",
			req:  request("10.1.2.3:80", "203.0.113.9, <script>, 10.7.7.7"),
			want: Info{Client: "10.7.7.7", Peer: "10.1.2.3", Forwarded: true},
		},
		{
			name: "empty entries are skipped",
			req:  request("10.1.2.3:80", " , 203.0.113.9 ,, "),
			want: Info{Client: "203.0.113.9", Peer: "10.1.2.3", Forwarded: true},
		},
		{
			name: "IPv4 entry with a port",
			req:  request("10.1.2.3:80", "203.0.113.9:51234"),
			want: Info{Client: "203.0.113.9", Peer: "10.1.2.3", Forwarded: true},
		},
		{
			name: "bracketed IPv6 entry with a port",
			req:  request("10.1.2.3:80", "[2001:db8::1]:443"),
			want: Info{Client: "2001:db8::1", Peer: "10.1.2.3", Forwarded: true},
		},
		{
			name: "bracketed IPv6 entry without a port",
			req:  request("10.1.2.3:80", "[2001:db8::1]"),
			want: Info{Client: "2001:db8::1", Peer: "10.1.2.3", Forwarded: true},
		},
		{
			name: "IPv6 entry is canonicalized",
			req:  request("10.1.2.3:80", "2001:0DB8:0000:0000:0000:0000:0000:0001"),
			want: Info{Client: "2001:db8::1", Peer: "10.1.2.3", Forwarded: true},
		},
		{
			name: "IPv6 peer in a trusted prefix",
			req:  request("[fd00::7]:80", "203.0.113.9"),
			want: Info{Client: "203.0.113.9", Peer: "fd00::7", Forwarded: true},
		},
		{
			// A dual-stack listener reports an IPv4 client as an IPv4-mapped IPv6
			// address; it is the same host and must match the IPv4 prefix.
			name: "IPv4-mapped peer matches the IPv4 prefix",
			req:  request("[::ffff:10.1.2.3]:80", "::ffff:203.0.113.9"),
			want: Info{Client: "203.0.113.9", Peer: "10.1.2.3", Forwarded: true},
		},
		{
			name: "zone is dropped",
			req:  request("[fe80::1%eth0]:80"),
			want: Info{Client: "fe80::1", Peer: "fe80::1"},
		},
		{
			name: "exact-address trust does not cover the neighbours",
			req:  request("192.168.7.8:80", "203.0.113.9"),
			want: Info{Client: "192.168.7.8", Peer: "192.168.7.8"},
		},
		{
			name: "non-IP peer is returned verbatim and never trusted",
			req:  request("@", "203.0.113.9"),
			want: Info{Client: "@", Peer: "@"},
		},
		{
			name: "peer without a port",
			req:  request("203.0.113.9"),
			want: Info{Client: "203.0.113.9", Peer: "203.0.113.9"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.Resolve(tc.req); got != tc.want {
				t.Fatalf("Resolve = %+v, want %+v", got, tc.want)
			}
		})
	}

	if got := r.Resolve(nil); got != (Info{}) {
		t.Fatalf("Resolve(nil) = %+v, want the zero Info", got)
	}
}

// A request cannot make the resolver do unbounded work: only a bounded number of
// entries is examined, and the answer then falls back to what was established.
func TestResolveBoundsTheChain(t *testing.T) {
	r := mustNew(t, "10.0.0.0/8")
	long := strings.Repeat("10.0.0.1, ", maxForwardedEntries+50)
	got := r.Resolve(request("10.1.2.3:80", "203.0.113.9, "+long+"10.0.0.2"))
	// The untrusted entry lies beyond the bound, so it is never reached; the
	// furthest trusted hop within the bound is reported instead.
	if got.Client != "10.0.0.1" || got.Peer != "10.1.2.3" || !got.Forwarded {
		t.Fatalf("Resolve = %+v, want the last trusted hop within the bound", got)
	}
}

func TestNewRejectsInvalidEntries(t *testing.T) {
	for _, bad := range []string{"not-an-ip", "10.0.0.0/33", "10.0.0.1/", "example.com", "10.0.0.1:80", "1.2.3"} {
		if _, err := New([]string{"10.0.0.0/8", bad}); err == nil {
			t.Errorf("New accepted %q", bad)
		}
	}
	r, err := New([]string{"", "  ", " 10.0.0.0/8 "})
	if err != nil {
		t.Fatalf("blank entries must be skipped: %v", err)
	}
	if !r.TrustsAny() {
		t.Fatal("TrustsAny() = false with a prefix configured")
	}
	if (*Resolver)(nil).TrustsAny() || mustNew(t).TrustsAny() {
		t.Fatal("TrustsAny() = true with nothing configured")
	}
}

func TestParsePrefixNormalizes(t *testing.T) {
	tests := map[string]string{
		"10.1.2.3":            "10.1.2.3/32",
		"10.1.2.3/8":          "10.0.0.0/8",
		"::ffff:10.1.2.3":     "10.1.2.3/32",
		"::ffff:10.0.0.0/104": "10.0.0.0/8",
		"2001:DB8::1":         "2001:db8::1/128",
		"2001:db8::1/32":      "2001:db8::/32",
		"0.0.0.0/0":           "0.0.0.0/0",
	}
	for in, want := range tests {
		got, err := ParsePrefix(in)
		if err != nil {
			t.Errorf("ParsePrefix(%q): %v", in, err)
			continue
		}
		if got.String() != want {
			t.Errorf("ParsePrefix(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestTrusted(t *testing.T) {
	r := mustNew(t, "10.0.0.0/8", "2001:db8::/32")
	for addr, want := range map[string]bool{
		"10.255.255.255":   true,
		"11.0.0.0":         false,
		"::ffff:10.0.0.1":  true,
		"2001:db8:ffff::1": true,
		"2001:db9::1":      false,
	} {
		if got := r.Trusted(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Trusted(%s) = %v, want %v", addr, got, want)
		}
	}
	if r.Trusted(netip.Addr{}) {
		t.Error("the zero address is trusted")
	}
}

func TestCanonical(t *testing.T) {
	for in, want := range map[string]string{
		"10.1.2.3":              "10.1.2.3",
		" 10.1.2.3 ":            "10.1.2.3",
		"::ffff:10.1.2.3":       "10.1.2.3",
		"2001:0db8:0:0:0:0:0:1": "2001:db8::1",
		"fe80::1%eth0":          "fe80::1",
	} {
		got, ok := Canonical(in)
		if !ok || got != want {
			t.Errorf("Canonical(%q) = %q, %v; want %q, true", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "nope", "10.1.2.3:80", "10.0.0.0/8"} {
		if got, ok := Canonical(bad); ok {
			t.Errorf("Canonical(%q) = %q, true; want false", bad, got)
		}
	}
}

func TestPeerAddr(t *testing.T) {
	host, addr, ok := PeerAddr("[2001:DB8::1]:443")
	if !ok || host != "2001:db8::1" || addr != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("PeerAddr = %q, %v, %v", host, addr, ok)
	}
	host, _, ok = PeerAddr("pipe")
	if ok || host != "pipe" {
		t.Fatalf("PeerAddr(pipe) = %q, %v; want the input, false", host, ok)
	}
}
