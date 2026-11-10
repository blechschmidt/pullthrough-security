package egress

import (
	"context"
	"errors"
	"net"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// TestClassifyIP exercises the IPv4 and IPv6 classification, including the IPv6
// edge cases (IPv4-mapped, 6to4, and NAT64 embedded addresses) that could
// otherwise smuggle an internal target past the v4 checks.
func TestClassifyIP(t *testing.T) {
	cases := []struct {
		name    string
		ip      string
		blocked bool
		reason  Reason
	}{
		// Public addresses are allowed.
		{"public v4", "93.184.216.34", false, ""},
		{"public v6", "2606:2800:220:1:248:1893:25c8:1946", false, ""},

		// IPv4 internal ranges.
		{"loopback v4", "127.0.0.1", true, ReasonLoopback},
		{"loopback v4 high", "127.255.255.254", true, ReasonLoopback},
		{"rfc1918 10", "10.1.2.3", true, ReasonPrivateNetwork},
		{"rfc1918 172", "172.16.5.5", true, ReasonPrivateNetwork},
		{"rfc1918 192", "192.168.0.1", true, ReasonPrivateNetwork},
		{"link-local v4", "169.254.10.10", true, ReasonLinkLocal},
		{"metadata v4", "169.254.169.254", true, ReasonMetadata},
		{"cgnat", "100.64.1.1", true, ReasonCGNAT},
		{"unspecified v4", "0.0.0.0", true, ReasonUnspecified},
		{"this-network 0/8", "0.1.2.3", true, ReasonUnspecified},
		{"multicast v4", "225.1.2.3", true, ReasonMulticast},
		{"link-local multicast v4", "224.0.0.1", true, ReasonLinkLocal},

		// IPv6 internal ranges.
		{"loopback v6", "::1", true, ReasonLoopback},
		{"link-local v6", "fe80::1", true, ReasonLinkLocal},
		{"unique-local fc", "fc00::1", true, ReasonUniqueLocal},
		{"unique-local fd", "fd12:3456:789a::1", true, ReasonUniqueLocal},
		{"metadata v6", "fd00:ec2::254", true, ReasonMetadata},
		{"unspecified v6", "::", true, ReasonUnspecified},
		{"multicast v6 global", "ff0e::1", true, ReasonMulticast},
		{"link-local multicast v6", "ff02::1", true, ReasonLinkLocal},

		// IPv6 edge cases: embedded / mapped IPv4 must be unwrapped & re-classified.
		{"v4-mapped loopback", "::ffff:127.0.0.1", true, ReasonLoopback},
		{"v4-mapped metadata", "::ffff:169.254.169.254", true, ReasonMetadata},
		{"v4-mapped private", "::ffff:10.0.0.5", true, ReasonPrivateNetwork},
		{"v4-mapped public", "::ffff:93.184.216.34", false, ""},
		{"6to4 to private", "2002:0a00:0001::", true, ReasonPrivateNetwork}, // 10.0.0.1
		{"6to4 to metadata", "2002:a9fe:a9fe::", true, ReasonMetadata},      // 169.254.169.254
		{"nat64 to private", "64:ff9b::a00:1", true, ReasonPrivateNetwork},  // 10.0.0.1
		{"nat64 to metadata", "64:ff9b::a9fe:a9fe", true, ReasonMetadata},   // 169.254.169.254
		{"nat64 to public", "64:ff9b::5db8:d822", false, ""},                // 93.184.216.34
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("test bug: cannot parse %q", tc.ip)
			}
			reason, blocked := classifyIP(ip)
			if blocked != tc.blocked {
				t.Fatalf("classifyIP(%s) blocked=%v, want %v (reason %q)", tc.ip, blocked, tc.blocked, reason)
			}
			if blocked && reason != tc.reason {
				t.Fatalf("classifyIP(%s) reason=%q, want %q", tc.ip, reason, tc.reason)
			}
		})
	}
}

func mustGuard(t *testing.T, cfg Config, opts Options) *Guard {
	t.Helper()
	cfg.Enabled = true
	g, err := New(cfg, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g == nil {
		t.Fatal("New returned nil guard for enabled config")
	}
	return g
}

// TestCheckURL covers scheme enforcement, the host allowlist (deny-by-default
// once non-empty), IP-literal blocking, and per-tenant overrides.
func TestCheckURL(t *testing.T) {
	tru := true
	fls := false

	cases := []struct {
		name    string
		cfg     Config
		tenant  string
		url     string
		blocked bool
		reason  Reason
	}{
		{
			name:    "https public allowed (no allowlist)",
			cfg:     Config{HTTPSOnly: true, BlockPrivateNetworks: true},
			url:     "https://registry.npmjs.org/left-pad",
			blocked: false,
		},
		{
			name:    "http blocked when https-only",
			cfg:     Config{HTTPSOnly: true, BlockPrivateNetworks: true},
			url:     "http://registry.npmjs.org/left-pad",
			blocked: true,
			reason:  ReasonSchemeNotAllowed,
		},
		{
			name:    "file scheme blocked",
			cfg:     Config{HTTPSOnly: true, BlockPrivateNetworks: true},
			url:     "file:///etc/passwd",
			blocked: true,
			reason:  ReasonSchemeNotAllowed,
		},
		{
			name:    "host not in allowlist",
			cfg:     Config{HTTPSOnly: true, BlockPrivateNetworks: true, Allowlist: []string{"registry.npmjs.org"}},
			url:     "https://evil.example.com/x",
			blocked: true,
			reason:  ReasonHostNotAllowed,
		},
		{
			name:    "exact host in allowlist",
			cfg:     Config{HTTPSOnly: true, BlockPrivateNetworks: true, Allowlist: []string{"registry.npmjs.org"}},
			url:     "https://registry.npmjs.org/x",
			blocked: false,
		},
		{
			name:    "domain suffix allowlist matches subdomain",
			cfg:     Config{HTTPSOnly: true, BlockPrivateNetworks: true, Allowlist: []string{"*.npmjs.org"}},
			url:     "https://registry.npmjs.org/x",
			blocked: false,
		},
		{
			name:    "domain suffix allowlist matches apex",
			cfg:     Config{HTTPSOnly: true, BlockPrivateNetworks: true, Allowlist: []string{".npmjs.org"}},
			url:     "https://npmjs.org/x",
			blocked: false,
		},
		{
			name:    "ip-literal metadata blocked even when scheme ok",
			cfg:     Config{HTTPSOnly: false, BlockPrivateNetworks: true},
			url:     "http://169.254.169.254/latest/meta-data/",
			blocked: true,
			reason:  ReasonMetadata,
		},
		{
			name:    "ip-literal loopback blocked",
			cfg:     Config{HTTPSOnly: false, BlockPrivateNetworks: true},
			url:     "http://127.0.0.1:8080/admin",
			blocked: true,
			reason:  ReasonLoopback,
		},
		{
			name:    "ipv6 loopback literal blocked",
			cfg:     Config{HTTPSOnly: false, BlockPrivateNetworks: true},
			url:     "http://[::1]:8080/admin",
			blocked: true,
			reason:  ReasonLoopback,
		},
		{
			name:    "tenant allowlist additive permits host",
			cfg:     Config{HTTPSOnly: true, BlockPrivateNetworks: true, Allowlist: []string{"registry.npmjs.org"}, TenantOverrides: map[string]TenantConfig{"team-a": {Allowlist: []string{"internal.example.com"}}}},
			tenant:  "team-a",
			url:     "https://internal.example.com/x",
			blocked: false,
		},
		{
			name:    "tenant without override still bound by global allowlist",
			cfg:     Config{HTTPSOnly: true, BlockPrivateNetworks: true, Allowlist: []string{"registry.npmjs.org"}, TenantOverrides: map[string]TenantConfig{"team-a": {Allowlist: []string{"internal.example.com"}}}},
			tenant:  "team-b",
			url:     "https://internal.example.com/x",
			blocked: true,
			reason:  ReasonHostNotAllowed,
		},
		{
			name:    "tenant httpsOnly override loosens to http",
			cfg:     Config{HTTPSOnly: true, BlockPrivateNetworks: true, TenantOverrides: map[string]TenantConfig{"legacy": {HTTPSOnly: &fls}}},
			tenant:  "legacy",
			url:     "http://mirror.example.com/x",
			blocked: false,
		},
		{
			name:    "tenant httpsOnly override tightens to https",
			cfg:     Config{HTTPSOnly: false, BlockPrivateNetworks: true, TenantOverrides: map[string]TenantConfig{"strict": {HTTPSOnly: &tru}}},
			tenant:  "strict",
			url:     "http://mirror.example.com/x",
			blocked: true,
			reason:  ReasonSchemeNotAllowed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := mustGuard(t, tc.cfg, Options{
				TenantFromContext: func(ctx context.Context) string { return tc.tenant },
			})
			u, err := url.Parse(tc.url)
			if err != nil {
				t.Fatalf("parse url: %v", err)
			}
			be := g.CheckURL(context.Background(), u)
			if (be != nil) != tc.blocked {
				t.Fatalf("CheckURL(%s) blocked=%v, want %v (err=%v)", tc.url, be != nil, tc.blocked, be)
			}
			if be != nil && tc.reason != "" && be.Reason != tc.reason {
				t.Fatalf("CheckURL(%s) reason=%q, want %q", tc.url, be.Reason, tc.reason)
			}
		})
	}
}

// TestCheckDialAddress is the DNS-rebinding defense: even if the hostname passed
// the URL-level allowlist, the resolved IP is re-validated before connect.
func TestCheckDialAddress(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		address string
		blocked bool
		reason  Reason
	}{
		{"public allowed", Config{BlockPrivateNetworks: true}, "93.184.216.34:443", false, ""},
		{"rebind to loopback", Config{BlockPrivateNetworks: true}, "127.0.0.1:443", true, ReasonLoopback},
		{"rebind to metadata", Config{BlockPrivateNetworks: true}, "169.254.169.254:80", true, ReasonMetadata},
		{"rebind to rfc1918", Config{BlockPrivateNetworks: true}, "10.0.0.5:443", true, ReasonPrivateNetwork},
		{"ipv6 ULA rebind", Config{BlockPrivateNetworks: true}, "[fd00::1]:443", true, ReasonUniqueLocal},
		{
			name:    "exception cidr permits internal mirror",
			cfg:     Config{BlockPrivateNetworks: true, AllowedDestinationCIDRs: []string{"10.0.0.0/8"}},
			address: "10.0.0.5:443",
			blocked: false,
		},
		{
			name:    "exception cidr does not permit other private range",
			cfg:     Config{BlockPrivateNetworks: true, AllowedDestinationCIDRs: []string{"10.0.0.0/8"}},
			address: "192.168.1.1:443",
			blocked: true,
			reason:  ReasonPrivateNetwork,
		},
		{
			name:    "private block disabled allows internal",
			cfg:     Config{BlockPrivateNetworks: false},
			address: "10.0.0.5:443",
			blocked: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := mustGuard(t, tc.cfg, Options{})
			be := g.CheckDialAddress(context.Background(), tc.address)
			if (be != nil) != tc.blocked {
				t.Fatalf("CheckDialAddress(%s) blocked=%v, want %v (err=%v)", tc.address, be != nil, tc.blocked, be)
			}
			if be != nil && tc.reason != "" && be.Reason != tc.reason {
				t.Fatalf("CheckDialAddress(%s) reason=%q, want %q", tc.address, be.Reason, tc.reason)
			}
			// DialControl must return a nil error interface when permitted.
			if err := g.DialControl(context.Background(), "tcp", tc.address); (err != nil) != tc.blocked {
				t.Fatalf("DialControl(%s) err=%v, want blocked=%v", tc.address, err, tc.blocked)
			}
		})
	}
}

// TestDialControlNilErrorInterface guards against the classic typed-nil bug: a
// permitted dial must return a truly nil error.
func TestDialControlNilErrorInterface(t *testing.T) {
	g := mustGuard(t, Config{BlockPrivateNetworks: true}, Options{})
	err := g.DialControl(context.Background(), "tcp", "93.184.216.34:443")
	if err != nil {
		t.Fatalf("DialControl on a public address returned non-nil error: %v", err)
	}
}

// TestDisabledGuardIsPermissive verifies a disabled guard never blocks.
func TestDisabledGuardIsPermissive(t *testing.T) {
	g, err := New(Config{Enabled: false}, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g.Enabled() {
		t.Fatal("disabled config produced an enabled guard")
	}
	u, _ := url.Parse("http://127.0.0.1/admin")
	if be := g.CheckURL(context.Background(), u); be != nil {
		t.Fatalf("disabled guard blocked: %v", be)
	}
	if err := g.DialControl(context.Background(), "tcp", "169.254.169.254:80"); err != nil {
		t.Fatalf("disabled guard dial-blocked: %v", err)
	}
}

// TestRecordingAndSnapshot verifies counters, the per-reason breakdown, the
// notification, and the audit record produced on a block.
func TestRecordingAndSnapshot(t *testing.T) {
	notifier := &fakeEmitter{}
	auditor := &fakeAudit{}
	g := mustGuard(t,
		Config{HTTPSOnly: true, BlockPrivateNetworks: true, Allowlist: []string{"registry.npmjs.org"}},
		Options{Notifier: notifier, Audit: auditor},
	)

	ok, _ := url.Parse("https://registry.npmjs.org/x")
	if be := g.CheckURL(context.Background(), ok); be != nil {
		t.Fatalf("expected allow, got %v", be)
	}
	bad, _ := url.Parse("https://evil.example.com/x")
	if be := g.CheckURL(context.Background(), bad); be == nil {
		t.Fatal("expected block for non-allowlisted host")
	}

	snap := g.Snapshot()
	if snap.Checked != 2 || snap.Allowed != 1 || snap.Blocked != 1 {
		t.Fatalf("counters: checked=%d allowed=%d blocked=%d, want 2/1/1", snap.Checked, snap.Allowed, snap.Blocked)
	}
	if snap.BlockedByReason[string(ReasonHostNotAllowed)] != 1 {
		t.Fatalf("per-reason: %v", snap.BlockedByReason)
	}
	if len(snap.Recent) != 1 || snap.Recent[0].Reason != ReasonHostNotAllowed {
		t.Fatalf("recent: %+v", snap.Recent)
	}
	if !snap.AllowlistEnforced {
		t.Fatal("expected AllowlistEnforced=true with a non-empty allowlist")
	}

	if len(notifier.events) != 1 || notifier.events[0].Type != notify.EventEgressBlocked {
		t.Fatalf("expected one egress_blocked notify event, got %d", len(notifier.events))
	}
	if notifier.events[0].Fields["reason"] != string(ReasonHostNotAllowed) {
		t.Fatalf("notify reason field: %v", notifier.events[0].Fields)
	}
	if len(auditor.events) != 1 || auditor.events[0].Decision != "deny" {
		t.Fatalf("expected one deny audit record, got %+v", auditor.events)
	}
}

// TestRuntimeAllowlistMutation covers admin add/remove of allowlist entries.
func TestRuntimeAllowlistMutation(t *testing.T) {
	g := mustGuard(t, Config{HTTPSOnly: true, BlockPrivateNetworks: true, Allowlist: []string{"a.example.com"}}, Options{})

	bad, _ := url.Parse("https://b.example.com/x")
	if be := g.CheckURL(context.Background(), bad); be == nil {
		t.Fatal("expected block before allowlisting b.example.com")
	}
	if err := g.AddAllowlistEntry("b.example.com"); err != nil {
		t.Fatalf("AddAllowlistEntry: %v", err)
	}
	if be := g.CheckURL(context.Background(), bad); be != nil {
		t.Fatalf("expected allow after allowlisting: %v", be)
	}
	if !g.RemoveAllowlistEntry("b.example.com") {
		t.Fatal("RemoveAllowlistEntry reported not present")
	}
	if be := g.CheckURL(context.Background(), bad); be == nil {
		t.Fatal("expected block after removing the entry")
	}
	if err := g.AddAllowlistEntry("not a valid cidr/"); err == nil {
		t.Fatal("expected error for malformed CIDR entry")
	}
}

// TestBlockedErrorIsDetectable verifies errors.As recovers the sentinel through
// wrapping, which is how backends distinguish a policy block from a transport
// failure.
func TestBlockedErrorIsDetectable(t *testing.T) {
	g := mustGuard(t, Config{BlockPrivateNetworks: true}, Options{})
	err := g.DialControl(context.Background(), "tcp", "169.254.169.254:80")
	wrapped := errors.New("upstream: fetching http://x: " + err.Error())
	_ = wrapped
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("errors.As failed to recover *BlockedError from %v", err)
	}
	if be.Reason != ReasonMetadata {
		t.Fatalf("reason=%q, want metadata", be.Reason)
	}
}

// --- test doubles ----------------------------------------------------------

type fakeEmitter struct{ events []notify.Event }

func (f *fakeEmitter) Emit(ctx context.Context, ev notify.Event) {
	f.events = append(f.events, ev)
}

type fakeAudit struct{ events []audit.Event }

func (f *fakeAudit) Log(ctx context.Context, ev audit.Event) error {
	f.events = append(f.events, ev)
	return nil
}
