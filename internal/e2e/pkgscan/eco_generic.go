//go:build integration
// +build integration

package pkgscan

// Generic (declarative backend): the upstream serves only what its routes
// match, and the routes are all the backend knows of the protocol. The row
// declares the two an operator fronting a release server writes:
//
//   - "index": a JSON index per package, served live with every absolute URL of
//     the upstream rewritten onto the proxy (`rewrite: true`): metadata;
//   - "releases": the release archives, cached, verified against the sibling
//     ".sha256" file the server publishes next to each, and listing the gate
//     (`gates: [llmPackageScan]`), which declares them installable payloads.
//
// A client reads the index and downloads the archive its "url" names. The
// archive is a gzip-compressed tar whose members sit under "<name>-<version>/".

func init() {
	register(eco{
		ID: "generic", Type: "generic", Title: "Generic (declarative backend)",
		Format: "release archive (.tar.gz) on a cacheable route listing the gate",
		Generic: map[string]any{
			"routes": []any{
				map[string]any{
					"name":    "index",
					"match":   `^/index/[^/]+\.json$`,
					"rewrite": true,
				},
				map[string]any{
					"name":      "releases",
					"match":     `^/releases/[^/]+/[^/]+\.tar\.gz$`,
					"cacheable": true,
					"mediaType": "application/gzip",
					"gates":     []any{"llmPackageScan"},
					"verify":    map[string]any{"algorithm": "sha256", "source": "sidecar", "sidecarSuffix": ".sha256"},
				},
			},
		},
		Registry: genericRegistry,
	})
}

func genericRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	for _, s := range env.Specs {
		name := s.Name()
		root := name + "-" + fixtureVersion + "/"
		file := name + "-" + fixtureVersion + ".tar.gz"
		archive := tarGz(map[string]string{
			root + "README.md":         "# " + name + "\n\npullthrough llm-package-scan e2e fixture.\n",
			root + "share/config.toml": "greeting = \"hello\"\n",
			root + markerFile:          s.Text(""),
		})
		release := "/releases/" + fixtureVersion + "/" + file
		index := "/index/" + name + ".json"
		reg.mux.File(release, archive, "application/gzip")
		// The checksum file, in the form sha256sum writes it.
		reg.mux.File(release+".sha256", []byte(hexOf(archive)+"  "+file+"\n"), "text/plain")
		reg.mux.File(index, jsonDoc(map[string]any{
			"name": name, "version": fixtureVersion,
			"url": env.URL + release, "sha256": hexOf(archive),
		}), "application/json")

		reg.add(s.Variant, &pkgPull{
			// The generic backend has no package grammar and derives no coordinate
			// from a path: a refusal names neither a package nor a version, and the
			// findings are recorded under the file name — the name the review and
			// the verdict give the artifact.
			Name: "", Version: "", FindingsName: file,
			// The index must send the client to the proxy for the archive.
			Preamble: []step{{Path: index, Contains: []string{mountPlaceholder + release}}},
			Payload:  step{Path: release},
			Body:     archive,
			Marker:   root + markerFile,
		})
	}
	return reg, nil
}
