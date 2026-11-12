//go:build integration
// +build integration

package pkgscan

// NuGet v3: the service index advertises the feed's resources as absolute URLs
// (the proxy rewrites those on its own host onto itself); the flat container
// lists a package's versions and serves the .nupkg, a zip.

func init() {
	register(eco{
		ID: "nuget", Type: "nuget", Title: "NuGet",
		Format:   "package (.nupkg, zip)",
		Registry: nugetRegistry,
	})
}

func nugetRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	reg.mux.File("/v3/index.json", jsonDoc(map[string]any{
		"version": "3.0.0",
		"resources": []map[string]string{
			{"@id": env.URL + "/v3-flatcontainer/", "@type": "PackageBaseAddress/3.0.0"},
			{"@id": env.URL + "/v3/registration5-gz-semver2/", "@type": "RegistrationsBaseUrl/3.6.0"},
		},
	}), "application/json")
	for _, s := range env.Specs {
		id := s.Name() // the flat container uses the lower-cased id
		nupkg := zipFiles(map[string]string{
			id + ".nuspec": "<?xml version=\"1.0\"?>\n<package><metadata><id>" + id + "</id><version>" + fixtureVersion +
				"</version><authors>pkgscan-e2e</authors><description>fixture</description></metadata></package>\n",
			"lib/netstandard2.0/_._": "",
			"content/" + markerFile:  s.Text(""),
		})
		base := "/v3-flatcontainer/" + id + "/"
		path := base + fixtureVersion + "/" + id + "." + fixtureVersion + ".nupkg"
		reg.mux.File(base+"index.json", jsonDoc(map[string]any{"versions": []string{fixtureVersion}}), "application/json")
		reg.mux.File(path, nupkg, "application/octet-stream")

		reg.add(s.Variant, &pkgPull{
			Name: id, Version: fixtureVersion,
			Preamble: []step{
				// A restore takes the package base address from the service index.
				{Path: "/v3/index.json", Contains: []string{mountPlaceholder + "/v3-flatcontainer/"}},
				{Path: base + "index.json", Contains: []string{fixtureVersion}},
			},
			Payload: step{Path: path},
			Body:    nupkg,
			Marker:  "content/" + markerFile,
		})
	}
	return reg, nil
}
