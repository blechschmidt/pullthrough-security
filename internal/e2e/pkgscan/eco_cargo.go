//go:build integration
// +build integration

package pkgscan

import "encoding/json"

// Cargo (sparse registry): config.json tells cargo where crates are downloaded
// from — the proxy rewrites that to itself —, an index file lists a crate's
// versions with their checksums, and the download endpoint serves the .crate,
// a gzip-compressed tar whose members sit under "<name>-<version>/".

func init() {
	register(eco{
		ID: "cargo", Type: "cargo", Title: "Cargo (crates.io)",
		Format: "crate (.crate, tar.gz)",
		// The stub plays the download host as well as the index.
		Settings: func(stub string) map[string]string { return map[string]string{"downloadUrl": stub} },
		Registry: cargoRegistry,
	})
}

func cargoRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	reg.mux.File("/config.json", jsonDoc(map[string]string{"dl": env.URL + "/api/v1/crates", "api": env.URL}), "application/json")
	for _, s := range env.Specs {
		name := s.Name()
		root := name + "-" + fixtureVersion + "/"
		crate := tarGz(map[string]string{
			root + "Cargo.toml": "[package]\nname = \"" + name + "\"\nversion = \"" + fixtureVersion + "\"\nedition = \"2021\"\n",
			root + "src/lib.rs": "pub fn answer() -> u32 { 42 }\n",
			root + markerFile:   s.Text(""),
		})
		download := "/api/v1/crates/" + name + "/" + fixtureVersion + "/download"
		reg.mux.File(download, crate, "application/gzip")
		// The sparse index fans names of four or more characters out as
		// "<first two>/<next two>/<name>".
		index := "/" + name[:2] + "/" + name[2:4] + "/" + name
		line, _ := json.Marshal(map[string]any{
			"name": name, "vers": fixtureVersion, "deps": []any{}, "cksum": hexOf(crate), "features": map[string]any{}, "yanked": false,
		})
		reg.mux.File(index, append(line, '\n'), "text/plain")

		reg.add(s.Variant, &pkgPull{
			Name: name, Version: fixtureVersion,
			Preamble: []step{
				// cargo downloads from wherever config.json's "dl" points.
				{Path: "/config.json", Contains: []string{mountPlaceholder + "/api/v1/crates"}},
				{Path: index, Contains: []string{hexOf(crate)}},
			},
			Payload: step{Path: download},
			Body:    crate,
			Marker:  root + markerFile,
		})
	}
	return reg, nil
}
