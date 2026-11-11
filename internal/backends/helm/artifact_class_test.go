package helm

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about
// every resource the classic chart-repository layout names: a chart archive is
// a payload by either path form, and its provenance file and the repository
// index are metadata. Calling a payload metadata would let it reach a client
// unexamined.
func TestResolveArtifactClass(t *testing.T) {
	b := testBackend(t, newFakeRepo(t), nil)

	cases := []struct {
		path string
		want backends.ArtifactClass
		// filename is the explicit Artifact.Filename; servedAs is what
		// ArtifactFilename() reports (the explicit name, else the last segment
		// of the upstream URL's path).
		filename string
		servedAs string
	}{
		// Payload: a chart archive by repository-relative path. The upstream URL
		// ends in the archive's own name, so none is stated.
		{"/nginx-1.2.3.tgz", backends.ArtifactPayload, "", "nginx-1.2.3.tgz"},
		{"/kube-state-metrics-5.0.1.tgz", backends.ArtifactPayload, "", "kube-state-metrics-5.0.1.tgz"},
		{"/charts/stable/mychart-2.0.0-rc.1.tgz", backends.ArtifactPayload, "", "mychart-2.0.0-rc.1.tgz"},

		// Payload: an index-resolved archive. Its upstream URL is the repository
		// index, so the archive's name — the last segment of the request — is
		// stated explicitly.
		{"/-/nginx/1.2.3/nginx-1.2.3.tgz", backends.ArtifactPayload, "nginx-1.2.3.tgz", "nginx-1.2.3.tgz"},
		{"/-/foo-2go/1.0.0/foo-2go-1.0.0.tgz", backends.ArtifactPayload, "foo-2go-1.0.0.tgz", "foo-2go-1.0.0.tgz"},
		// The link keeps the basename of the location the index lists, whatever
		// it is: an archive is a payload under any name, including one that reads
		// like an index.
		{"/-/query/1.0.0/download", backends.ArtifactPayload, "download", "download"},
		{"/-/odd/1.0.0/odd_name.tar.gz", backends.ArtifactPayload, "odd_name.tar.gz", "odd_name.tar.gz"},
		{"/-/sly/1.0.0/index.yaml", backends.ArtifactPayload, "index.yaml", "index.yaml"},

		// Metadata: a provenance file, by either path form.
		{"/nginx-1.2.3.tgz.prov", backends.ArtifactMetadata, "", "nginx-1.2.3.tgz.prov"},
		{"/charts/stable/mychart-2.0.0-rc.1.tgz.prov", backends.ArtifactMetadata, "", "mychart-2.0.0-rc.1.tgz.prov"},
		{"/-/nginx/1.2.3/nginx-1.2.3.tgz.prov", backends.ArtifactMetadata, "nginx-1.2.3.tgz.prov", "nginx-1.2.3.tgz.prov"},
		{"/-/query/1.0.0/download.prov", backends.ArtifactMetadata, "download.prov", "download.prov"},

		// Metadata: the repository index, and another repository's index found
		// deeper in the tree.
		{"/index.yaml", backends.ArtifactMetadata, "", "index.yaml"},
		{"/stable/index.yaml", backends.ArtifactMetadata, "", "index.yaml"},
	}
	for _, c := range cases {
		res := resolve(t, b, c.path)
		if res.Artifact.Class != c.want {
			t.Errorf("Resolve(%q).Artifact.Class = %s, want %s", c.path, res.Artifact.Class, c.want)
		}
		if res.Artifact.Filename != c.filename {
			t.Errorf("Resolve(%q).Artifact.Filename = %q, want %q", c.path, res.Artifact.Filename, c.filename)
		}
		if got := res.ArtifactFilename(); got != c.servedAs {
			t.Errorf("Resolve(%q).ArtifactFilename() = %q, want %q", c.path, got, c.servedAs)
		}
		if res.Artifact.Kind != "" {
			t.Errorf("Resolve(%q).Artifact.Kind = %q, want none", c.path, res.Artifact.Kind)
		}
	}
}

// TestIndexedArchiveArtifactNameIsNotTheIndex shows why an index-resolved
// resource states its file name: the path of its upstream URL ends in
// "index.yaml" (the entry it names is the fragment), and a gate that named the
// payload after that URL would take a chart archive for the index.
func TestIndexedArchiveArtifactNameIsNotTheIndex(t *testing.T) {
	b := testBackend(t, newFakeRepo(t), nil)
	res := resolve(t, b, "/-/nginx/1.2.3/nginx-1.2.3.tgz")

	u, err := url.Parse(res.UpstreamURL)
	if err != nil {
		t.Fatalf("upstream URL %q does not parse: %v", res.UpstreamURL, err)
	}
	if !strings.HasSuffix(u.Path, "/"+indexFile) || u.Fragment != "nginx/1.2.3/nginx-1.2.3.tgz" {
		t.Fatalf("upstream URL = %q, want the repository index with the entry as its fragment", res.UpstreamURL)
	}
	if res.Artifact != backends.PayloadNamed("nginx-1.2.3.tgz") {
		t.Errorf("Artifact = %+v, want a payload named nginx-1.2.3.tgz", res.Artifact)
	}
	if got := res.ArtifactFilename(); got == indexFile {
		t.Errorf("ArtifactFilename() = %q: the archive is named after the index", got)
	}
}

// TestRewrittenArchiveLinksArePayloads ties the classification to the index
// rewrite: whatever location an index lists for an archive, the link the
// rewritten index hands out for it resolves to a payload named by the link's
// last segment. No archive link can come back as metadata — in particular not
// by ending in ".prov", which the rewrite never mints for an archive.
func TestRewrittenArchiveLinksArePayloads(t *testing.T) {
	b := testBackend(t, newFakeRepo(t), nil)
	const chart, version = "c", "1.0.0"
	for _, location := range []string{
		"https://h.example/charts/c-1.0.0.tgz",
		"charts/c-1.0.0.tgz",
		"https://h.example/dl/odd_name.tar.gz",
		"https://h.example/download?id=42",
		"https://h.example/",
		"https://h.example/index.yaml",
		"https://h.example/c-1.0.0.tgz.prov",
		"https://h.example/release.prov",
		"oci://registry.example/charts/c:1.0.0",
		"ftp://h.example/c-1.0.0.tgz",
	} {
		file := archiveFile(location, chart, version)
		link := (linker{}).archive(chart, version, file)
		u, err := url.Parse(link)
		if err != nil {
			t.Fatalf("link %q for %q does not parse: %v", link, location, err)
		}
		// The gateway hands Resolve the decoded path below the mount.
		res := resolve(t, b, "/"+u.Path)
		if res.Artifact != backends.PayloadNamed(file) {
			t.Errorf("location %q: link %q resolves to %+v, want a payload named %q", location, link, res.Artifact, file)
		}
	}
}

// TestIndexedArchiveKeepsItsClassificationThroughFetch fetches index-resolved
// archives from the two kinds of location an index lists — another HTTP host
// and an OCI registry — and checks that what the gates are handed with the
// bytes is still the chart's classification. The registry pull resolves
// manifests and blobs through a docker backend of its own; none of that may
// replace what Resolve said about the chart.
func TestIndexedArchiveKeepsItsClassificationThroughFetch(t *testing.T) {
	s := newRepoSetup(t)
	b := s.backend(t, Options{PublicBaseURL: publicBase})

	for _, c := range []struct {
		path string
		want backends.Artifact
	}{
		{"/-/foreign/3.0.0/foreign-3.0.0.tgz", backends.PayloadNamed("foreign-3.0.0.tgz")},
		{"/-/ocihosted/5.0.0/ocihosted-5.0.0.tgz", backends.PayloadNamed("ocihosted-5.0.0.tgz")},
		{"/-/foreign/3.0.0/foreign-3.0.0.tgz.prov", backends.Artifact{Class: backends.ArtifactMetadata, Filename: "foreign-3.0.0.tgz.prov"}},
		{"/-/ocihosted/5.0.0/ocihosted-5.0.0.tgz.prov", backends.Artifact{Class: backends.ArtifactMetadata, Filename: "ocihosted-5.0.0.tgz.prov"}},
		{"/charts/relative-2.0.0.tgz", backends.Payload()},
	} {
		fres, body, err := fetchPath(t, b, c.path)
		if err != nil || len(body) == 0 {
			t.Errorf("fetch %s: %d bytes, %v", c.path, len(body), err)
			continue
		}
		if fres.Resolved.Artifact != c.want {
			t.Errorf("fetch %s: Resolved.Artifact = %+v, want %+v", c.path, fres.Resolved.Artifact, c.want)
		}
	}
}

// TestOCIModeReturnsTheRegistryClassification covers the OCI transport, where
// the Helm backend is a front for the docker backend: the classification of a
// manifest, a blob or a listing is the registry backend's, and the Helm backend
// must hand it on untouched — neither replacing nor clearing it. The
// expectation is therefore the delegate's own answer for the same request, for
// every route the registry grammar names.
func TestOCIModeReturnsTheRegistryClassification(t *testing.T) {
	b, err := New(Options{
		Name:        "ocicharts",
		UpstreamURL: "https://registry-1.docker.io",
		Client:      upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
		OCI:         true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	digest := "sha256:" + strings.Repeat("ab", 32)
	for _, path := range []string{
		"/v2/",
		"/v2/charts/nginx/manifests/1.2.3",
		"/v2/charts/nginx/manifests/" + digest,
		"/v2/charts/nginx/blobs/" + digest,
		"/v2/charts/nginx/referrers/" + digest,
		"/v2/charts/nginx/tags/list",
		"/v2/_catalog",
	} {
		request := func() *backends.Request {
			return &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}}
		}
		want, err := b.oci.Resolve(context.Background(), request())
		if err != nil {
			t.Fatalf("registry Resolve(%q): %v", path, err)
		}
		got, err := b.Resolve(context.Background(), request())
		if err != nil {
			t.Fatalf("Resolve(%q): %v", path, err)
		}
		if got.Artifact != want.Artifact {
			t.Errorf("Resolve(%q).Artifact = %+v, want the registry backend's %+v", path, got.Artifact, want.Artifact)
		}
		// Nothing else of the delegated resolution is altered either: the one
		// addition is the key that marks a manifest request as a chart pull.
		delete(got.Metadata, metaOCI)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Resolve(%q) = %+v, want the registry backend's resolution %+v", path, got, want)
		}
	}
}
