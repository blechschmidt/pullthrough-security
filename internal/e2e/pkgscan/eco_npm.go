//go:build integration
// +build integration

package pkgscan

import (
	"crypto/sha1"
	"encoding/hex"
)

// npm: a registry serves a packument (the package's metadata document, whose
// dist.tarball URLs the proxy rewrites onto itself) and the package tarball,
// "/<name>/-/<name>-<version>.tgz", whose members sit under "package/".

func init() {
	register(eco{
		ID: "npm", Type: "npm", Title: "npm",
		Format:   "package tarball (.tgz)",
		Registry: npmRegistry,
	})
}

func npmRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	for _, s := range env.Specs {
		name := s.Name()
		path := "/" + name + "/-/" + name + "-" + fixtureVersion + ".tgz"
		tarball := tarGz(map[string]string{
			"package/package.json":  string(jsonDoc(map[string]any{"name": name, "version": fixtureVersion, "main": "index.js"})),
			"package/index.js":      "module.exports = function () { return 1; };\n",
			"package/" + markerFile: s.Text(""),
		})
		shasum := sha1.Sum(tarball)
		reg.mux.File(path, tarball, "application/octet-stream")
		reg.mux.File("/"+name, jsonDoc(map[string]any{
			"name":      name,
			"dist-tags": map[string]string{"latest": fixtureVersion},
			"versions": map[string]any{fixtureVersion: map[string]any{
				"name": name, "version": fixtureVersion,
				"dist": map[string]string{"tarball": env.URL + path, "shasum": hex.EncodeToString(shasum[:])},
			}},
		}), "application/json")

		reg.add(s.Variant, &pkgPull{
			Name: name, Version: fixtureVersion,
			// `npm install` reads the packument and downloads the tarball it names:
			// the proxy must have pointed that link at itself.
			Preamble: []step{{Path: "/" + name, Contains: []string{mountPlaceholder + path}}},
			Payload:  step{Path: path},
			Body:     tarball,
			Marker:   "package/" + markerFile,
		})
	}
	return reg, nil
}
