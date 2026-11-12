//go:build integration
// +build integration

package pkgscan

import (
	"net/http"
)

// Helm, OCI registry (`helm pull oci://…`, upstream setting `oci: "true"`): the
// helm backend fronts the Docker / OCI registry backend, and a chart is an OCI
// artifact — a manifest naming a config blob (the chart's metadata, as JSON)
// and one layer blob (the chart archive `helm package` writes). The gate
// examines the chart when its manifest is pulled, fetching the blobs itself;
// the row pulls the manifest by tag, as `helm pull --version` does, which the
// backend never caches.

func init() {
	register(eco{
		ID: "helm-oci", Type: "helm", Title: "Helm (OCI registry)",
		Format:   "OCI chart: manifest (by tag) + chart layer (.tgz)",
		Settings: func(string) map[string]string { return map[string]string{"oci": "true"} },
		Registry: helmOCIRegistry,
	})
}

// Media types of a chart pushed by `helm push`.
const (
	helmOCIManifestType = "application/vnd.oci.image.manifest.v1+json"
	helmOCIConfigType   = "application/vnd.cncf.helm.config.v1+json"
	helmOCILayerType    = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
)

// helmOCIAccept is the content negotiation of Helm's registry client
// (oras-go): every manifest and index media type it can read.
var helmOCIAccept = http.Header{"Accept": {
	mediaDockerManifest,
	"application/vnd.docker.distribution.manifest.list.v2+json",
	helmOCIManifestType,
	"application/vnd.oci.image.index.v1+json",
}}

// helmOCIChart is the chart of a spec as an OCI artifact: the classic row's
// archive as the layer, under "charts/<chart>" in the registry.
func helmOCIChart(s pkgSpec) ociArtifact {
	name, archive := helmChart(s)
	return ociArtifact{
		Repo: "charts/" + name, Tag: fixtureVersion,
		ManifestType: helmOCIManifestType, ConfigType: helmOCIConfigType, LayerType: helmOCILayerType,
		// What `helm push` stores as the config: Chart.yaml, as JSON.
		Config: jsonDoc(map[string]any{
			"apiVersion": "v2", "name": name, "version": fixtureVersion, "appVersion": fixtureVersion,
			"description": "pullthrough llm-package-scan e2e fixture", "type": "application",
		}),
		Layer:  archive,
		Marker: name + "/" + markerFile,
	}
}

func helmOCIRegistry(env stubEnv) (*registry, error) {
	reg := ociRegistry(env, helmOCIChart)
	for _, s := range env.Specs {
		a := helmOCIChart(s)
		p := reg.pulls[s.Variant]
		p.Payload.Header = helmOCIAccept
		// Only the chart layer follows the verdict on the manifest. The config blob
		// of a chart is its metadata, not an image config, and the gate implicates
		// a config in a refusal only when it reads as an image config: a manifest
		// can name any blob of the registry as its config, so a refusal must not be
		// able to take an unrelated blob offline (see internal/llmpkgscan/blobs.go).
		// A refused chart's config blob is therefore still served, by design.
		p.Followers = []step{{Path: "/v2/" + a.Repo + "/blobs/" + digestOf(a.Layer)}}
	}
	return reg, nil
}
