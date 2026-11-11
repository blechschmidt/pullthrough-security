package terraform

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about
// every path of the two registry protocols: the module source archive and the
// provider ZIP are payloads, the endpoints the protocols define are metadata,
// and the remaining registry paths — forwarded as-is — are left unclassified
// for a gate to judge from the bytes. Calling a payload metadata would let it
// reach a client unexamined.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeRegistry(t), nil)

	const (
		payload      = backends.ArtifactPayload
		metadata     = backends.ArtifactMetadata
		unclassified = backends.ArtifactUnclassified
	)
	cases := []struct {
		path string
		want backends.ArtifactClass
		// filename is the explicit Artifact.Filename, stated for the two
		// artifacts whose upstream URL is the registry endpoint that locates
		// them.
		filename string
	}{
		// Payload: the proxy-synthetic module source archive.
		{"/v1/modules/hashicorp/consul/aws/1.0.0/archive", payload, "module-archive"},
		// Payload: the proxy-synthetic provider ZIP, named the way registries
		// publish it, from the coordinates in the path.
		{"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64/zip", payload, "terraform-provider-aws_5.0.0_linux_amd64.zip"},
		{"/v1/providers/hashicorp/null/3.2.1/download/windows/arm64/zip", payload, "terraform-provider-null_3.2.1_windows_arm64.zip"},

		// Metadata: service discovery, synthesized by the proxy.
		{"/.well-known/terraform.json", metadata, ""},
		// Metadata: the module registry protocol's endpoints.
		{"/v1/modules/hashicorp/consul/aws/versions", metadata, ""},
		{"/v1/modules/hashicorp/consul/aws/1.0.0/download", metadata, ""},
		{"/v1/modules/hashicorp/consul/aws/download", metadata, ""},
		// Metadata: the provider registry protocol's endpoints, and the SHASUMS
		// manifest and signature the proxy serves next to the ZIP.
		{"/v1/providers/hashicorp/aws/versions", metadata, ""},
		{"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64", metadata, ""},
		{"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64/shasums", metadata, ""},
		{"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64/shasums.sig", metadata, ""},

		// Unclassified: every other path under the two API roots. They are
		// forwarded as-is; the grammar does not say what a registry serves there.
		{"/v1/modules", unclassified, ""},
		{"/v1/modules/search", unclassified, ""},
		{"/v1/modules/hashicorp/consul", unclassified, ""},
		{"/v1/modules/hashicorp/consul/aws", unclassified, ""},
		{"/v1/modules/hashicorp/consul/aws/1.0.0", unclassified, ""},
		{"/v1/modules/hashicorp/consul/aws/1.0.0/source.tgz", unclassified, ""},
		{"/v1/modules/hashicorp/consul/aws/1.0.0/archive/module.zip", unclassified, ""},
		{"/v1/providers", unclassified, ""},
		{"/v1/providers/hashicorp/aws", unclassified, ""},
		{"/v1/providers/hashicorp/aws/5.0.0", unclassified, ""},
		{"/v1/providers/hashicorp/aws/5.0.0/terraform-provider-aws_5.0.0_linux_amd64.zip", unclassified, ""},
		{"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64/terraform-provider-aws_5.0.0_linux_amd64.zip", unclassified, ""},
		{"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64/zip/extra", unclassified, ""},
	}
	for _, c := range cases {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: c.path, Query: url.Values{}})
		if err != nil {
			t.Errorf("Resolve(%q): %v", c.path, err)
			continue
		}
		if res.Artifact.Class != c.want {
			t.Errorf("Resolve(%q).Artifact.Class = %s, want %s (kind %s)", c.path, res.Artifact.Class, c.want, res.Metadata[metaKind])
		}
		if res.Artifact.Filename != c.filename {
			t.Errorf("Resolve(%q).Artifact.Filename = %q, want %q", c.path, res.Artifact.Filename, c.filename)
		}
		if res.Artifact.Kind != "" {
			t.Errorf("Resolve(%q).Artifact.Kind = %q, want none", c.path, res.Artifact.Kind)
		}
	}
}

// TestArtifactNamesAreNotTheRegistryEndpoints shows why the two payloads state
// a file name: the upstream URL of the module archive is the registry's
// download endpoint and that of the provider ZIP is the package descriptor, so
// a gate that named the payload after the URL would call a module "download"
// and a provider ZIP "amd64".
func TestArtifactNamesAreNotTheRegistryEndpoints(t *testing.T) {
	b := newTestBackend(t, newFakeRegistry(t), nil)
	for path, endpoint := range map[string]string{
		"/v1/modules/hashicorp/consul/aws/1.0.0/archive":             "/v1/modules/hashicorp/consul/aws/1.0.0/download",
		"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64/zip": "/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64",
	} {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
		if err != nil {
			t.Fatalf("Resolve(%q): %v", path, err)
		}
		if !strings.HasSuffix(res.UpstreamURL, endpoint) {
			t.Fatalf("Resolve(%q).UpstreamURL = %q, want the registry endpoint %s", path, res.UpstreamURL, endpoint)
		}
		last := endpoint[strings.LastIndexByte(endpoint, '/')+1:]
		if got := res.ArtifactFilename(); got == last || got == "" || got != res.Artifact.Filename {
			t.Errorf("Resolve(%q).ArtifactFilename() = %q, want the artifact's stated name %q", path, got, res.Artifact.Filename)
		}
	}
}

// TestArtifactOfIncompleteOrUnknownResource covers the two branches Resolve
// cannot reach through classify: a provider ZIP whose coordinates are missing
// still gets a ZIP name, and the zero kind makes no statement at all.
func TestArtifactOfIncompleteOrUnknownResource(t *testing.T) {
	for _, r := range []resource{
		{kind: kindProviderZip},
		{kind: kindProviderZip, namespace: "hashicorp", name: "aws", version: "5.0.0"},
		{kind: kindProviderZip, namespace: "hashicorp", name: "aws", version: "5.0.0", os: "linux"},
	} {
		if got := r.artifact(); got != backends.PayloadNamed("terraform-provider.zip") {
			t.Errorf("%+v.artifact() = %+v, want a payload named terraform-provider.zip", r, got)
		}
	}
	if got := (resource{kind: kindOther}).artifact(); got != (backends.Artifact{}) {
		t.Errorf("kindOther.artifact() = %+v, want no statement", got)
	}
}

// followed returns the path, below the backend's mount, that a client requests
// when it resolves location against the URL it asked the backend at — the way
// Terraform resolves a relative X-Terraform-Get or download_url.
func followed(t *testing.T, askedPath, location string) string {
	t.Helper()
	const host, mount = "https://proxy.example", "/v1/tf"
	asked, err := url.Parse(host + mount + askedPath)
	if err != nil {
		t.Fatalf("parsing %q: %v", askedPath, err)
	}
	ref, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parsing %q: %v", location, err)
	}
	target := asked.ResolveReference(ref)
	path, ok := strings.CutPrefix(target.Path, mount)
	if !ok || target.Host != asked.Host {
		t.Fatalf("%q resolves to %s, outside the mount", location, target)
	}
	return path
}

// TestRelativeArtifactLocationsAreNotCalledMetadata is the reason the two
// catch-all kinds (module-meta, provider-meta) are left unclassified. Both
// registry protocols let a registry give an artifact's location relative to the
// endpoint that announces it. The backend forwards such a location unchanged,
// the client resolves it against the URL it asked — a URL of this mount — and
// then downloads the archive from a registry path the grammar does not name.
// That path serves a payload, so it must not be classified as metadata.
func TestRelativeArtifactLocationsAreNotCalledMetadata(t *testing.T) {
	t.Run("module source", func(t *testing.T) {
		fr := newFakeRegistry(t)
		const download = "/v1/modules/acme/vpc/aws/1.2.0/download"
		archive := []byte("\x1f\x8b module source archive")
		fr.statuses[download] = http.StatusNoContent
		fr.headers[download] = http.Header{"X-Terraform-Get": {"./source.tgz"}}
		fr.files["/v1/modules/acme/vpc/aws/1.2.0/source.tgz"] = archive
		b := newTestBackend(t, fr, &Metrics{})

		fres, _, err := resolveFetch(t, b, download)
		if err != nil {
			t.Fatalf("fetch download endpoint: %v", err)
		}
		location := fres.Header.Get("X-Terraform-Get")
		if location != "./source.tgz" {
			t.Fatalf("X-Terraform-Get = %q, want the relative location forwarded unchanged", location)
		}
		assertServedButNotMetadata(t, b, followed(t, download, location), "module-meta", archive)
	})

	t.Run("provider archive", func(t *testing.T) {
		fr := newFakeRegistry(t)
		const descriptor = "/v1/providers/acme/widget/1.0.0/download/linux/amd64"
		zip := []byte("PK\x03\x04 provider archive")
		desc, _ := json.Marshal(map[string]any{
			"protocols":    []string{"5.0"},
			"os":           "linux",
			"arch":         "amd64",
			"filename":     "terraform-provider-widget_1.0.0_linux_amd64.zip",
			"download_url": "../../terraform-provider-widget_1.0.0_linux_amd64.zip",
			"shasum":       sha256Hex(zip),
		})
		fr.files[descriptor] = desc
		fr.files["/v1/providers/acme/widget/1.0.0/terraform-provider-widget_1.0.0_linux_amd64.zip"] = zip
		// No public base URL: the descriptor cannot be rewritten and is forwarded
		// as the registry sent it.
		b, err := New(Options{
			Name:        "tf",
			UpstreamURL: fr.srv.URL,
			Client:      upstream.NewWithHTTPClient(fr.srv.Client(), "test/1"),
			Metrics:     &Metrics{},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		_, body, err := resolveFetch(t, b, descriptor)
		if err != nil {
			t.Fatalf("fetch descriptor: %v", err)
		}
		var served struct {
			DownloadURL string `json:"download_url"`
		}
		if err := json.Unmarshal(body, &served); err != nil || served.DownloadURL != "../../terraform-provider-widget_1.0.0_linux_amd64.zip" {
			t.Fatalf("download_url = %q (%v), want the relative location forwarded unchanged", served.DownloadURL, err)
		}
		assertServedButNotMetadata(t, b, followed(t, descriptor, served.DownloadURL), "provider-meta", zip)
	})
}

// assertServedButNotMetadata checks that path is a resource of the given
// catch-all kind which the backend serves (content is what the registry holds
// there) and which Resolve does not classify as metadata.
func assertServedButNotMetadata(t *testing.T, b *Backend, path, kind string, content []byte) {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve(%q): %v", path, err)
	}
	if res.Metadata[metaKind] != kind {
		t.Fatalf("Resolve(%q) kind = %q, want %q", path, res.Metadata[metaKind], kind)
	}
	if res.Artifact.Class == backends.ArtifactMetadata {
		t.Errorf("Resolve(%q).Artifact.Class = %s for a path that serves an archive", path, res.Artifact.Class)
	}
	_, body, err := resolveFetch(t, b, path)
	if err != nil || !bytes.Equal(body, content) {
		t.Errorf("fetch %s: %q, %v; want the archive the registry serves there", path, body, err)
	}
}
