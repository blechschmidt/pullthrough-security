package hex

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about
// every resource the Hex layout names: a release tarball and a Hex/Rebar build
// are payloads, the signed registry resources and the builds lists are
// metadata. Calling a payload metadata would let it reach a client unexamined,
// so the /installs/ tree — which serves both classes, uncached — is covered
// shape by shape.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil)

	cases := []struct {
		path      string
		want      backends.ArtifactClass
		cacheable bool
	}{
		// Payloads: release tarballs.
		{"/tarballs/jason-1.4.1.tar", backends.ArtifactPayload, true},
		{"/tarballs/plug_cowboy-2.6.1.tar", backends.ArtifactPayload, true},
		{"/tarballs/foo-1.0.0-rc.1.tar", backends.ArtifactPayload, true},

		// Payloads: the Hex and Rebar builds Mix installs and runs. They are
		// served live, so "not cacheable" must not be read as "not a payload".
		{"/installs/1.15.0/hex-2.0.6.ez", backends.ArtifactPayload, false},
		{"/installs/1.18.0/hex-2.7.0-otp-27.ez", backends.ArtifactPayload, false},
		{"/installs/1.14.5/rebar3-3.22.0", backends.ArtifactPayload, false},
		{"/installs/1.18.4/rebar3-3.28.0-otp-28", backends.ArtifactPayload, false},
		{"/installs/1.13.0/rebar-2.6.4", backends.ArtifactPayload, false},
		// A build whose "version" spells a list name is still a build: only a
		// single segment directly below /installs/ can be a list.
		{"/installs/1.16.0/rebar3-1.x.csv", backends.ArtifactPayload, false},
		{"/installs/1.16.0/rebar-1.csv.signed", backends.ArtifactPayload, false},

		// Metadata: the signed registry resources.
		{"/names", backends.ArtifactMetadata, false},
		{"/versions", backends.ArtifactMetadata, false},
		{"/packages/jason", backends.ArtifactMetadata, false},

		// Metadata: the builds lists and their detached signatures.
		{"/installs/hex-1.x.csv", backends.ArtifactMetadata, false},
		{"/installs/hex-1.x.csv.signed", backends.ArtifactMetadata, false},
		{"/installs/rebar3-1.x.csv", backends.ArtifactMetadata, false},
		{"/installs/rebar3-1.x.csv.signed", backends.ArtifactMetadata, false},
		{"/installs/rebar-1.x.csv", backends.ArtifactMetadata, false},
		{"/installs/hex.csv", backends.ArtifactMetadata, false},
		{"/installs/rebar.csv.signed", backends.ArtifactMetadata, false},
	}
	for _, c := range cases {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: c.path, Query: url.Values{}})
		if err != nil {
			t.Errorf("Resolve(%q): %v", c.path, err)
			continue
		}
		if res.Artifact.Class != c.want {
			t.Errorf("Resolve(%q).Artifact.Class = %s, want %s", c.path, res.Artifact.Class, c.want)
		}
		if res.Cacheable != c.cacheable {
			t.Errorf("Resolve(%q).Cacheable = %v, want %v", c.path, res.Cacheable, c.cacheable)
		}
		// Every Hex resource is fetched from a URL that ends in its own file
		// name, so no explicit name (and no payload refinement) is stated.
		// An install build is one file (an escript, a Mix archive); a package
		// tarball is an archive.
		wantKind := backends.ArtifactKind("")
		if res.Artifact.Class == backends.ArtifactPayload && strings.HasPrefix(c.path, "/installs/") {
			wantKind = backends.KindFile
		}
		if res.Artifact.Filename != "" || res.Artifact.Kind != wantKind {
			t.Errorf("Resolve(%q).Artifact = %+v, want only a class", c.path, res.Artifact)
		}
	}
}

// TestInstallArtifactClassFollowsGrammar ties the classification to the
// /installs/ grammar: of the paths the real clients request, exactly the
// single-segment lists are metadata and every two-segment build is a payload,
// so no build can be reported as metadata.
func TestInstallArtifactClassFollowsGrammar(t *testing.T) {
	for _, p := range []string{
		"/installs/hex-1.x.csv",
		"/installs/hex-1.x.csv.signed",
		"/installs/rebar3-1.x.csv",
		"/installs/rebar3-1.x.csv.signed",
		"/installs/rebar-1.x.csv",
		"/installs/rebar-1.x.csv.signed",
		"/installs/hex.csv",
		"/installs/hex.csv.signed",
		"/installs/rebar.csv",
		"/installs/rebar.csv.signed",
		"/installs/1.16.0/hex-2.7.0.ez",
		"/installs/1.18.0/hex-2.7.0-otp-27.ez",
		"/installs/1.14.5/rebar3-3.22.0",
		"/installs/1.15.0-rc.0/rebar3-3.22.0",
		"/installs/1.18.4/rebar3-3.28.0-otp-28",
		"/installs/1.13.0/rebar-2.6.4",
		"/installs/1.0.0/hex-0.14.0.ez",
	} {
		res, ok := classify(p)
		if !ok || res.kind != kindInstall {
			t.Fatalf("classify(%q) = %+v ok=%v, want an install resource", p, res, ok)
		}
		want := backends.ArtifactMetadata
		if strings.Contains(res.filename, "/") {
			want = backends.ArtifactPayload
		}
		if got := res.artifact().Class; got != want {
			t.Errorf("classify(%q).artifact().Class = %s, want %s", p, got, want)
		}
	}
}
