//go:build integration
// +build integration

package pkgscan

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"
)

// Swift Package Registry (SE-0292). A package is "<scope>.<name>"; SwiftPM asks
// the registry it is configured with, and builds every URL from that base:
//
//   - "/<scope>/<name>": the release list;
//   - "/<scope>/<name>/<version>": the release metadata, whose "resources" name
//     the source archive with its SHA-256 "checksum";
//   - "/<scope>/<name>/<version>/Package.swift": the manifest, a Swift program
//     SwiftPM compiles and runs — a payload of its own, examined on its own, so
//     it is served by the stub but kept out of the preamble;
//   - "/<scope>/<name>/<version>.zip": the source archive, the payload pulled
//     here. On a miss the proxy reads the checksum from the release metadata and
//     verifies the archive against it before serving it.
//
// Every request names the API version in its Accept header, and every answer
// carries "Content-Version: 1". The archive's members sit under one top-level
// directory named after the package, which SwiftPM strips when it unpacks it.

func init() {
	register(eco{
		ID: "swift", Type: "swift", Title: "Swift package registry",
		Format:   "source archive (.zip)",
		Registry: swiftRegistry,
	})
}

// The media types a SwiftPM client accepts, per resource.
const (
	swiftAcceptJSON = "application/vnd.swift.registry.v1+json"
	swiftAcceptZip  = "application/vnd.swift.registry.v1+zip"
)

// swiftScope is the scope every fixture is published under.
const swiftScope = "pte2e"

func swiftRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	for _, s := range env.Specs {
		name := s.Slug() // the package identity is pte2e.<variant>
		manifest := "// swift-tools-version:5.9\nimport PackageDescription\n\nlet package = Package(\n" +
			"    name: \"" + name + "\",\n" +
			"    products: [.library(name: \"" + name + "\", targets: [\"" + name + "\"])],\n" +
			"    targets: [.target(name: \"" + name + "\")]\n)\n"
		archive := zipFiles(map[string]string{
			name + "/Package.swift":                           manifest,
			name + "/Sources/" + name + "/" + name + ".swift": "public func answer() -> Int { 42 }\n",
			name + "/" + markerFile:                           s.Text(""),
		})

		base := "/" + swiftScope + "/" + name
		release := base + "/" + fixtureVersion
		// A release's "url" names the registry's own host, as a registry writes it;
		// SwiftPM does not follow it, which is why the proxy leaves it alone.
		swiftFile(reg.mux, base, jsonDoc(map[string]any{
			"releases": map[string]any{fixtureVersion: map[string]string{"url": env.URL + release}},
		}), "application/json")
		swiftFile(reg.mux, release, jsonDoc(map[string]any{
			"id":      swiftScope + "." + name,
			"version": fixtureVersion,
			"resources": []map[string]string{{
				"name": "source-archive", "type": "application/zip", "checksum": hexOf(archive),
			}},
			"metadata":    map[string]any{"description": "pkgscan e2e fixture", "repositoryURLs": []string{"https://example.invalid/pte2e/" + name + ".git"}},
			"publishedAt": stubModTime.Format(time.RFC3339),
		}), "application/json")
		swiftFile(reg.mux, release+"/Package.swift", []byte(manifest), "text/x-swift")
		swiftFile(reg.mux, release+".zip", archive, "application/zip")

		acceptJSON := http.Header{"Accept": {swiftAcceptJSON}}
		reg.add(s.Variant, &pkgPull{
			Name: swiftScope + "." + name, Version: fixtureVersion,
			Preamble: []step{
				{Path: base, Header: acceptJSON, Contains: []string{fixtureVersion}},
				// What SwiftPM verifies the archive against: the registry's checksum.
				{Path: release, Header: acceptJSON, Contains: []string{hexOf(archive)}},
			},
			Payload: step{Path: release + ".zip", Header: http.Header{"Accept": {swiftAcceptZip}}},
			Body:    archive,
			Marker:  name + "/" + markerFile,
		})
	}
	return reg, nil
}

// swiftFile serves a registry resource with the headers a Swift registry sends:
// the API version, and — on an archive — the SHA-256 "Digest" the client may
// check it against.
func swiftFile(m *stubMux, path string, body []byte, contentType string) {
	sum := sha256.Sum256(body)
	digest := "sha-256=" + base64.StdEncoding.EncodeToString(sum[:])
	m.Handle(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Version", "1")
		if contentType == "application/zip" {
			w.Header().Set("Digest", digest)
		}
		w.Header().Set("Content-Type", contentType)
		http.ServeContent(w, r, "", stubModTime, bytes.NewReader(body))
	})
}
