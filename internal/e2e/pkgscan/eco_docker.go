//go:build integration
// +build integration

package pkgscan

import (
	"net/http"
)

// Docker / OCI registry: an image is a manifest naming a config blob and layer
// blobs, each fetched by a request of its own. The gate examines the image as
// a whole when its manifest is pulled — the proxy fetches the config and the
// layers itself for that — and the blobs then follow the image's verdict.
//
// The row pulls the manifest by tag, which the backend never caches: the
// response is held in a spool until the verdict exists.

func init() {
	register(eco{
		ID: "docker", Type: "docker", Title: "Docker / OCI registry",
		Format:   "OCI image: manifest (by tag) + config + layer (tar.gz)",
		Registry: func(env stubEnv) (*registry, error) { return ociRegistry(env, dockerImage), nil },
	})
}

// Media types of a Docker image.
const (
	mediaDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mediaDockerConfig   = "application/vnd.docker.container.image.v1+json"
	mediaDockerLayer    = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

// ociArtifact is what an OCI repository holds for one package: a config blob
// and one layer blob, under the media types of its artifact kind.
type ociArtifact struct {
	// Repo is the repository name, Tag the tag the manifest is published under.
	Repo, Tag string
	// ManifestType, ConfigType and LayerType are the media types.
	ManifestType, ConfigType, LayerType string
	// Config and Layer are the blobs.
	Config, Layer []byte
	// Marker is the marker file's path below the layer's directory in the
	// scanner's listing.
	Marker string
}

// dockerImage builds a minimal container image for a spec: one layer holding
// the application directory, and a config that starts a script from it.
func dockerImage(s pkgSpec) ociArtifact {
	layerTar := tarOf(
		member{Name: "app/run.sh", Data: "#!/bin/sh\necho \"hello from the pkgscan e2e image\"\n", Mode: 0o755},
		member{Name: "app/" + markerFile, Data: s.Text("")},
	)
	config := jsonDoc(map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"config":       map[string]any{"Entrypoint": []string{"/app/run.sh"}, "WorkingDir": "/app", "User": "nobody"},
		"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{digestOf(layerTar)}},
		"history":      []map[string]any{{"created_by": "COPY app /app", "created": "2024-01-02T03:04:05Z"}},
	})
	return ociArtifact{
		Repo: "pte2e/" + s.Slug(), Tag: fixtureVersion,
		ManifestType: mediaDockerManifest, ConfigType: mediaDockerConfig, LayerType: mediaDockerLayer,
		Config: config, Layer: gzipOf(layerTar),
		Marker: "app/" + markerFile,
	}
}

// ociRegistry builds a stub Registry v2 serving one artifact per spec. It is
// shared by every row whose upstream is an OCI registry.
func ociRegistry(env stubEnv, build func(pkgSpec) ociArtifact) *registry {
	reg := newRegistry()
	// The API version probe every client starts with. An unauthenticated 200
	// tells the proxy there is no token to obtain.
	reg.mux.Handle("/v2/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	})
	for _, s := range env.Specs {
		a := build(s)
		manifest := jsonDoc(map[string]any{
			"schemaVersion": 2,
			"mediaType":     a.ManifestType,
			"config":        map[string]any{"mediaType": a.ConfigType, "size": len(a.Config), "digest": digestOf(a.Config)},
			"layers":        []map[string]any{{"mediaType": a.LayerType, "size": len(a.Layer), "digest": digestOf(a.Layer)}},
		})
		manifestDigest := digestOf(manifest)
		serveManifest := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", a.ManifestType)
			w.Header().Set("Docker-Content-Digest", manifestDigest)
			if r.Method != http.MethodHead {
				_, _ = w.Write(manifest)
			}
		}
		base := "/v2/" + a.Repo
		reg.mux.Handle(base+"/manifests/"+a.Tag, serveManifest)
		reg.mux.Handle(base+"/manifests/"+manifestDigest, serveManifest)
		reg.mux.File(base+"/blobs/"+digestOf(a.Config), a.Config, "application/octet-stream")
		reg.mux.File(base+"/blobs/"+digestOf(a.Layer), a.Layer, "application/octet-stream")

		accept := http.Header{"Accept": {a.ManifestType, "application/vnd.oci.image.manifest.v1+json", "application/vnd.oci.image.index.v1+json"}}
		reg.add(s.Variant, &pkgPull{
			Name: a.Repo, Version: a.Tag,
			Preamble: []step{{Path: "/v2/"}},
			Payload:  step{Path: base + "/manifests/" + a.Tag, Header: accept},
			Body:     manifest,
			// The scanner lists a layer's files under layers/<NNN>-<digest prefix>/,
			// numbered from the base layer up.
			Marker: "layers/001-" + hexOf(a.Layer)[:12] + "/" + a.Marker,
			// What a client fetches once it has the manifest. Each follows the
			// verdict on the image.
			Followers: []step{
				{Path: base + "/blobs/" + digestOf(a.Config)},
				{Path: base + "/blobs/" + digestOf(a.Layer)},
			},
			Uncached: true,
		})
	}
	return reg
}
