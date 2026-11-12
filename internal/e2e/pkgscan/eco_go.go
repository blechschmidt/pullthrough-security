//go:build integration
// +build integration

package pkgscan

// Go modules (GOPROXY protocol): "/<module>/@v/list", "<version>.info",
// "<version>.mod" and "<version>.zip". The zip is the payload; its members sit
// under "<module>@<version>/".

func init() {
	register(eco{
		ID: "go", Type: "go", Title: "Go modules (GOPROXY)",
		Format:   "module zip",
		Registry: goRegistry,
	})
}

func goRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	const version = "v" + fixtureVersion
	for _, s := range env.Specs {
		module := "example.test/pte2e/" + s.Slug()
		root := module + "@" + version + "/"
		gomod := "module " + module + "\n\ngo 1.21\n"
		zip := zipFiles(map[string]string{
			root + "go.mod":   gomod,
			root + "lib.go":   "package " + s.Slug() + "\n\n// Answer returns 42.\nfunc Answer() int { return 42 }\n",
			root + markerFile: s.Text(""),
		})
		base := "/" + module + "/@v/"
		reg.mux.File(base+"list", []byte(version+"\n"), "text/plain")
		reg.mux.File(base+version+".info", jsonDoc(map[string]string{"Version": version, "Time": "2024-01-02T03:04:05Z"}), "application/json")
		reg.mux.File(base+version+".mod", []byte(gomod), "text/plain")
		reg.mux.File(base+version+".zip", zip, "application/zip")

		reg.add(s.Variant, &pkgPull{
			Name: module, Version: version,
			// What `go mod download` asks a GOPROXY for, in order.
			Preamble: []step{
				{Path: base + "list", Contains: []string{version}},
				{Path: base + version + ".info", Contains: []string{version}},
				{Path: base + version + ".mod", Contains: []string{"module " + module}},
			},
			Payload: step{Path: base + version + ".zip"},
			Body:    zip,
			Marker:  root + markerFile,
		})
	}
	return reg, nil
}
