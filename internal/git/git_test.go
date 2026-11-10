package git

import (
	"errors"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func TestPktLine(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "0004"},
		{"a", "0005a"},
		{"# service=git-upload-pack\n", "001e# service=git-upload-pack\n"},
	}
	for _, c := range cases {
		if got := pktLine(c.in); got != c.want {
			t.Errorf("pktLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestServiceAdvertisementHeader(t *testing.T) {
	got := serviceAdvertisementHeader(serviceUploadPack)
	want := "001e# service=git-upload-pack\n0000"
	if got != want {
		t.Errorf("serviceAdvertisementHeader = %q, want %q", got, want)
	}
}

func TestValidateService(t *testing.T) {
	if got, err := validateService(serviceUploadPack); err != nil || got != serviceUploadPack {
		t.Errorf("upload-pack: got %q err %v", got, err)
	}
	if _, err := validateService(serviceReceivePack); !errors.Is(err, ErrPushRejected) {
		t.Errorf("receive-pack: err = %v, want ErrPushRejected", err)
	}
	if _, err := validateService(""); !errors.Is(err, ErrInvalidService) {
		t.Errorf("empty: err = %v, want ErrInvalidService", err)
	}
	if _, err := validateService("git-bogus"); !errors.Is(err, ErrInvalidService) {
		t.Errorf("bogus: err = %v, want ErrInvalidService", err)
	}
}

func TestSplitRepoEndpoint(t *testing.T) {
	cases := []struct {
		in       string
		repo     string
		endpoint gitEndpoint
		ok       bool
	}{
		{"/owner/repo.git/info/refs", "owner/repo.git", endpointInfoRefs, true},
		{"owner/repo.git/git-upload-pack", "owner/repo.git", endpointUploadPack, true},
		{"/a/b/c.git/git-receive-pack", "a/b/c.git", endpointReceivePack, true},
		{"/info/refs", "", endpointInfoRefs, true},
		{"/owner/repo.git/objects/info/packs", "", endpointUnknown, false},
		{"/owner/repo.git", "", endpointUnknown, false},
	}
	for _, c := range cases {
		repo, ep, ok := splitRepoEndpoint(c.in)
		if ok != c.ok || repo != c.repo || ep != c.endpoint {
			t.Errorf("splitRepoEndpoint(%q) = (%q,%v,%v), want (%q,%v,%v)",
				c.in, repo, ep, ok, c.repo, c.endpoint, c.ok)
		}
	}
}

func TestSanitizeRepoPath(t *testing.T) {
	ok := map[string]string{
		"owner/repo.git":   "owner/repo.git",
		"/owner/repo.git/": "owner/repo.git",
		"a/b/c":            "a/b/c",
		"owner/./repo":     "owner/repo",
	}
	for in, want := range ok {
		got, err := sanitizeRepoPath(in)
		if err != nil || got != want {
			t.Errorf("sanitizeRepoPath(%q) = (%q,%v), want (%q,nil)", in, got, err, want)
		}
	}

	bad := []string{"", "/", "..", "../etc/passwd", "owner/../../etc", "a/../../b", "x\x00y"}
	for _, in := range bad {
		if got, err := sanitizeRepoPath(in); err == nil {
			t.Errorf("sanitizeRepoPath(%q) = %q, want error", in, got)
		}
	}
}

func TestNewUpstreamTransport(t *testing.T) {
	client := upstream.NewWithHTTPClient(nil, "test/1")
	cases := []struct {
		url       string
		transport Transport
	}{
		{"https://github.com", TransportHTTPS},
		{"https://ghe.corp/git", TransportHTTPS},
		{"ssh://git@github.com", TransportSSH},
		{"git@github.com:org", TransportSSH},
	}
	for _, c := range cases {
		up, err := NewUpstream(UpstreamOptions{Name: "u", URL: c.url, Client: client})
		if err != nil {
			t.Fatalf("NewUpstream(%q): %v", c.url, err)
		}
		if up.Transport != c.transport {
			t.Errorf("NewUpstream(%q).Transport = %v, want %v", c.url, up.Transport, c.transport)
		}
	}

	if _, err := NewUpstream(UpstreamOptions{Name: "u", URL: "ftp://x/y"}); err == nil {
		t.Error("expected error for unsupported scheme")
	}
	if _, err := NewUpstream(UpstreamOptions{Name: "", URL: "https://x"}); err == nil {
		t.Error("expected error for empty name")
	}
}

func TestUpstreamHTTPURL(t *testing.T) {
	client := upstream.NewWithHTTPClient(nil, "test/1")
	up, err := NewUpstream(UpstreamOptions{Name: "gh", URL: "https://github.com", Client: client})
	if err != nil {
		t.Fatal(err)
	}
	got, err := up.upstreamHTTPURL("owner/repo.git", "/info/refs", url.Values{"service": {serviceUploadPack}})
	if err != nil {
		t.Fatal(err)
	}
	want := "https://github.com/owner/repo.git/info/refs?service=git-upload-pack"
	if got != want {
		t.Errorf("upstreamHTTPURL = %q, want %q", got, want)
	}

	// Base path prefix must be preserved.
	up2, _ := NewUpstream(UpstreamOptions{Name: "ghe", URL: "https://ghe.corp/git", Client: client})
	got2, _ := up2.upstreamHTTPURL("o/r.git", "/git-upload-pack", nil)
	if want2 := "https://ghe.corp/git/o/r.git/git-upload-pack"; got2 != want2 {
		t.Errorf("upstreamHTTPURL = %q, want %q", got2, want2)
	}
}

func TestUpstreamCloneURLCredentials(t *testing.T) {
	client := upstream.NewWithHTTPClient(nil, "test/1")

	token, _ := NewUpstream(UpstreamOptions{Name: "gh", URL: "https://github.com", Client: client, Credentials: upstream.Credentials{Token: "secret"}})
	if got := token.upstreamCloneURL("o/r.git"); got != "https://x-access-token:secret@github.com/o/r.git" {
		t.Errorf("token clone url = %q", got)
	}
	if red := token.redactedCloneURL("o/r.git"); red != "https://github.com/o/r.git" {
		t.Errorf("redacted clone url leaked credentials: %q", red)
	}

	basic, _ := NewUpstream(UpstreamOptions{Name: "gh", URL: "https://github.com", Client: client, Credentials: upstream.Credentials{Username: "u", Password: "p"}})
	if got := basic.upstreamCloneURL("o/r.git"); got != "https://u:p@github.com/o/r.git" {
		t.Errorf("basic clone url = %q", got)
	}

	ssh, _ := NewUpstream(UpstreamOptions{Name: "gh", URL: "ssh://git@github.com", Client: client})
	if got := ssh.upstreamCloneURL("o/r.git"); got != "git@github.com:o/r.git" {
		t.Errorf("ssh clone url = %q", got)
	}
}

func TestParseGitCommand(t *testing.T) {
	cases := []struct {
		in      string
		service string
		repo    string
		wantErr bool
	}{
		{"git-upload-pack 'github/owner/repo.git'", "git-upload-pack", "github/owner/repo.git", false},
		{`git-upload-pack "gh/o/r.git"`, "git-upload-pack", "gh/o/r.git", false},
		{"git-receive-pack 'gh/o/r.git'", "git-receive-pack", "gh/o/r.git", false},
		{"git-upload-pack", "", "", true},
		{"", "", "", true},
	}
	for _, c := range cases {
		svc, repo, err := parseGitCommand(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseGitCommand(%q): expected error", c.in)
			}
			continue
		}
		if err != nil || svc != c.service || repo != c.repo {
			t.Errorf("parseGitCommand(%q) = (%q,%q,%v)", c.in, svc, repo, err)
		}
	}
}

func TestSplitUpstreamRepo(t *testing.T) {
	cases := []struct {
		in   string
		name string
		repo string
		ok   bool
	}{
		{"/github/owner/repo.git", "github", "owner/repo.git", true},
		{"github/owner/repo.git", "github", "owner/repo.git", true},
		{"github", "", "", false},
		{"/github", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		name, repo, ok := splitUpstreamRepo(c.in)
		if ok != c.ok || name != c.name || repo != c.repo {
			t.Errorf("splitUpstreamRepo(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.in, name, repo, ok, c.name, c.repo, c.ok)
		}
	}
}

func TestDecodeExecPayload(t *testing.T) {
	// SSH string: 4-byte length prefix + data.
	payload := []byte{0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o'}
	if got := decodeExecPayload(payload); got != "hello" {
		t.Errorf("decodeExecPayload = %q, want hello", got)
	}
	if got := decodeExecPayload([]byte{0, 1}); got != "" {
		t.Errorf("short payload: got %q", got)
	}
}
