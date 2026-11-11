package bazel

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about
// every resource the registry layout names. The source archive, MODULE.bazel,
// patches and overlay files are all build inputs — payloads; only the three
// JSON descriptors are metadata. Calling a payload metadata would let it reach
// a client unexamined.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil, "https://proxy.example/v1/bazel")

	cases := []struct {
		path string
		want backends.ArtifactClass
		// filename is the explicit Artifact.Filename; servedAs is what
		// ArtifactFilename() reports (the explicit name, else the last segment
		// of the upstream URL).
		filename string
		servedAs string
	}{
		// Payload: the proxy-synthetic source archive. Its upstream URL is the
		// module's source.json, so the archive's own name is stated explicitly.
		{"/modules/platforms/0.0.10/archive", backends.ArtifactPayload, "archive", "archive"},
		{"/modules/platforms/0.0.10/archive/", backends.ArtifactPayload, "archive", "archive"},
		{"/modules/platforms/0.0.10/archive/platforms-0.0.10.tar.gz", backends.ArtifactPayload, "platforms-0.0.10.tar.gz", "platforms-0.0.10.tar.gz"},
		{"/modules/rules_go/0.50.1/archive/rules_go-v0.50.1.zip", backends.ArtifactPayload, "rules_go-v0.50.1.zip", "rules_go-v0.50.1.zip"},
		// The trailing name is the client's spelling, reported as given.
		{"/modules/platforms/0.0.10/archive/anything", backends.ArtifactPayload, "anything", "anything"},

		// Payload: single files Bazel evaluates or applies to the source tree.
		{"/modules/platforms/0.0.10/MODULE.bazel", backends.ArtifactPayload, "", "MODULE.bazel"},
		{"/modules/rules_go/0.50.1/patches/fix.patch", backends.ArtifactPayload, "", "fix.patch"},
		{"/modules/rules_go/0.50.1/patches/module_dot_bazel.diff", backends.ArtifactPayload, "", "module_dot_bazel.diff"},
		{"/modules/zlib/1.3.1.bcr.3/overlay/BUILD.bazel", backends.ArtifactPayload, "", "BUILD.bazel"},
		{"/modules/zlib/1.3.1.bcr.3/overlay/src/lib/MODULE.bazel", backends.ArtifactPayload, "", "MODULE.bazel"},
		// An overlay file is a payload whatever it is called, including a name a
		// descriptor would carry elsewhere in the layout.
		{"/modules/zlib/1.3.1.bcr.3/overlay/source.json", backends.ArtifactPayload, "", "source.json"},
		{"/modules/zlib/1.3.1.bcr.3/overlay/metadata.json", backends.ArtifactPayload, "", "metadata.json"},

		// Metadata: the JSON descriptors.
		{"/bazel_registry.json", backends.ArtifactMetadata, "", "bazel_registry.json"},
		{"/modules/platforms/metadata.json", backends.ArtifactMetadata, "", "metadata.json"},
		{"/modules/platforms/0.0.10/source.json", backends.ArtifactMetadata, "", "source.json"},
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
		if res.Artifact.Filename != c.filename {
			t.Errorf("Resolve(%q).Artifact.Filename = %q, want %q", c.path, res.Artifact.Filename, c.filename)
		}
		if got := res.ArtifactFilename(); got != c.servedAs {
			t.Errorf("Resolve(%q).ArtifactFilename() = %q, want %q", c.path, got, c.servedAs)
		}
		// A module file, a patch and an overlay file are single files; the source
		// archive is an archive. Nothing else is refined.
		wantKind := backends.ArtifactKind("")
		if res.Artifact.Class == backends.ArtifactPayload && !strings.Contains(c.path, "/archive") {
			wantKind = backends.KindFile
		}
		if res.Artifact.Kind != wantKind {
			t.Errorf("Resolve(%q).Artifact.Kind = %q, want %q", c.path, res.Artifact.Kind, wantKind)
		}
	}
}

// TestArchiveArtifactNameIsNotTheDescriptor shows why the archive states its
// file name: the resolved upstream URL is the module's source.json, and a gate
// that named the payload after that URL would take the archive for a JSON
// document.
func TestArchiveArtifactNameIsNotTheDescriptor(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil, "https://proxy.example/v1/bazel")
	for _, path := range []string{
		"/modules/platforms/0.0.10/archive",
		"/modules/platforms/0.0.10/archive/platforms-0.0.10.tar.gz",
	} {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
		if err != nil {
			t.Fatalf("Resolve(%q): %v", path, err)
		}
		if !strings.HasSuffix(res.UpstreamURL, "/modules/platforms/0.0.10/"+sourceFile) {
			t.Fatalf("Resolve(%q).UpstreamURL = %q, want the module's source.json", path, res.UpstreamURL)
		}
		if got := res.ArtifactFilename(); got == sourceFile || got == "" {
			t.Errorf("Resolve(%q).ArtifactFilename() = %q, want the archive's name", path, got)
		}
		if res.Artifact.Class != backends.ArtifactPayload {
			t.Errorf("Resolve(%q).Artifact.Class = %s, want payload", path, res.Artifact.Class)
		}
	}
}
