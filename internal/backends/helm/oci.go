package helm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/docker"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// A classic repository index may list a chart archive not as an HTTP URL but as
// an OCI reference ("oci://<registry>/<repository>:<tag>"): the chart was pushed
// to a registry and the index merely points at it. Bitnami's index does this for
// every chart version it has published since moving to OCI. A Helm client
// follows such a reference by pulling from the registry itself, so — exactly
// like an absolute URL on another host — it would take the download around the
// proxy. The index rewrite therefore replaces these references too, and the
// backend performs the registry pull when the archive is requested.
//
// A Helm chart stored as an OCI artifact is a manifest whose layers hold the
// packaged chart (and, optionally, its provenance file) verbatim: the chart
// layer is the very .tgz a classic archive URL would serve. So the backend reads
// the manifest the reference names, picks the layer of the wanted media type,
// and streams that blob; the SHA-256 the index declares for the chart applies to
// it unchanged and is enforced like for any other location.
//
// The registry conversation (token handshake, digest-addressed blobs verified
// as they stream) is the Docker/OCI backend's, driven through this backend's
// own upstream client, so the egress guard governs a registry host like any
// other. Pulls are anonymous: the upstream's credentials belong to the chart
// repository and are never offered to a registry an index entry names. Charts
// in a private registry are served by the OCI mode instead.

const (
	ociScheme = "oci"

	// Media types of the layers of a Helm chart OCI artifact.
	ociChartLayer      = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
	ociProvenanceLayer = "application/vnd.cncf.helm.chart.provenance.v1.prov"

	// ociManifestAccept asks for an image manifest, the shape a chart artifact
	// takes; registries predating OCI media types answer with the Docker one.
	ociManifestAccept = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

	// maxOCIManifestBytes bounds a chart manifest read into memory. A chart
	// manifest lists a config and one to three layers: well under a kilobyte.
	maxOCIManifestBytes = 1 << 20 // 1 MiB
)

// ociReference is a parsed "oci://" chart location.
type ociReference struct {
	// registry is the registry host (with port, when given).
	registry string
	// repository is the artifact's repository path within the registry.
	repository string
	// reference is the tag or the digest ("sha256:<hex>") naming the artifact.
	reference string
}

// parseOCIReference splits an oci:// URL into registry, repository and
// reference. The reference is required: an index entry names one chart version,
// and a tagless reference would name whatever the registry calls "latest".
func parseOCIReference(u *url.URL) (ociReference, error) {
	ref := ociReference{registry: u.Host}
	path := strings.Trim(u.Path, "/")
	switch {
	case strings.Contains(path, "@"):
		// <repository>[:<tag>]@<digest>: the digest is what pins the content.
		i := strings.LastIndex(path, "@")
		ref.repository, ref.reference = path[:i], path[i+1:]
		if j := strings.LastIndex(ref.repository, ":"); j > strings.LastIndex(ref.repository, "/") {
			ref.repository = ref.repository[:j]
		}
	case strings.LastIndex(path, ":") > strings.LastIndex(path, "/"):
		i := strings.LastIndex(path, ":")
		ref.repository, ref.reference = path[:i], path[i+1:]
	}
	if ref.registry == "" || ref.repository == "" || ref.reference == "" {
		return ociReference{}, fmt.Errorf("the index lists it at %q, which is not a complete OCI reference (registry/repository:tag)", u.String())
	}
	// Docker Hub's registry API lives on registry-1.docker.io; "docker.io" is the
	// name references use for it.
	if ref.registry == "docker.io" || ref.registry == "index.docker.io" {
		ref.registry = "registry-1.docker.io"
	}
	return ref, nil
}

// fetchOCILocation serves an index-resolved request whose listed location is an
// OCI reference: the chart layer of the referenced artifact, verified against
// the digest the index entry declares, or its provenance layer.
func (b *Backend) fetchOCILocation(ctx context.Context, resolved *backends.Resolved, loc chartLocation, target *url.URL) (*backends.FetchResult, error) {
	ref, err := parseOCIReference(target)
	if err != nil {
		return nil, err
	}
	registry, err := docker.New(docker.Options{
		Name:        b.name,
		UpstreamURL: "https://" + ref.registry,
		Client:      b.client,
	})
	if err != nil {
		return nil, fmt.Errorf("the index lists it at %q: %w", target.String(), err)
	}

	provenance := resolved.Metadata[MetaProvenance] == "1"
	mediaType := ociChartLayer
	if provenance {
		mediaType = ociProvenanceLayer
	}
	digest, err := ociLayerDigest(ctx, registry, ref, mediaType)
	if err != nil {
		return nil, err
	}
	blob, err := ociFetch(ctx, registry, "/v2/"+ref.repository+"/blobs/"+digest, "")
	if err != nil {
		return nil, err
	}

	resolved.Metadata[MetaArchiveURL] = displayURL(target)
	if provenance {
		b.metrics.incProvenanceServed()
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   blob.Content,
			Size:      blob.Size,
			MediaType: "text/plain; charset=utf-8",
			Header:    make(http.Header),
			Status:    http.StatusOK,
		}, nil
	}
	expected, haveChecksum := loc.checksum()
	return b.chartResult(resolved, &upstream.Response{
		Status:        http.StatusOK,
		Body:          blob.Content,
		ContentLength: blob.Size,
		ContentType:   "application/gzip",
	}, make(http.Header), expected, haveChecksum, target.String()), nil
}

// ociLayerDigest reads the manifest ref names and returns the digest of its
// layer of the given media type. A manifest without such a layer is not a chart
// (or, for the provenance layer, a chart published without provenance, which is
// reported the way a missing .prov file is: 404).
func ociLayerDigest(ctx context.Context, registry *docker.Backend, ref ociReference, mediaType string) (string, error) {
	manifestPath := "/v2/" + ref.repository + "/manifests/" + ref.reference
	res, err := ociFetch(ctx, registry, manifestPath, ociManifestAccept)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(res.Content, maxOCIManifestBytes+1))
	_ = res.Content.Close()
	if err != nil {
		return "", fmt.Errorf("reading the manifest of %s/%s:%s: %w", ref.registry, ref.repository, ref.reference, err)
	}
	var manifest struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
		} `json:"layers"`
	}
	if len(body) > maxOCIManifestBytes || json.Unmarshal(body, &manifest) != nil {
		return "", fmt.Errorf("%s/%s:%s does not have a usable manifest", ref.registry, ref.repository, ref.reference)
	}
	for _, layer := range manifest.Layers {
		if layer.MediaType == mediaType && docker.IsDigest(layer.Digest) {
			return layer.Digest, nil
		}
	}
	if mediaType == ociProvenanceLayer {
		return "", &backends.StatusError{
			Status: http.StatusNotFound,
			URL:    "oci://" + ref.registry + "/" + ref.repository + ":" + ref.reference,
			Body:   "the chart artifact carries no provenance layer",
		}
	}
	return "", fmt.Errorf("%s/%s:%s is not a Helm chart artifact (no %s layer)", ref.registry, ref.repository, ref.reference, mediaType)
}

// ociFetch performs one registry request through the Docker/OCI backend, which
// runs the token handshake as needed and, for a blob, verifies the streamed
// content against the digest in its path.
func ociFetch(ctx context.Context, registry *docker.Backend, path, accept string) (*backends.FetchResult, error) {
	req := &backends.Request{Method: http.MethodGet, Path: path, Header: make(http.Header)}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resolved, err := registry.Resolve(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%q is not a registry path the index reference can name: %w", path, err)
	}
	res, err := registry.Fetch(ctx, resolved)
	if err != nil {
		return nil, err
	}
	if res.NotModified || res.Content == nil {
		return nil, fmt.Errorf("the registry returned no content for %s", resolved.UpstreamURL)
	}
	return res, nil
}
