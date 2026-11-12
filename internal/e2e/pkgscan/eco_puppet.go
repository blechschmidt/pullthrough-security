//go:build integration
// +build integration

package pkgscan

import (
	"crypto/md5"
	"encoding/hex"
)

// Puppet Forge (v3 API): r10k installing `mod '<owner>-<name>', '<version>'`
// reads the release document, "/v3/releases/<owner>-<name>-<version>", and
// downloads its `file_uri` — a path relative to the Forge's base URL, so with
// the proxy mount as the base the download comes back through the proxy without
// any rewriting — then checks the file against `file_sha256` (or `file_md5`).
// The backend verifies the release tarball against the same document, which it
// fetches itself. A release tarball is a gzip-compressed tar whose members sit
// under "<owner>-<name>-<version>/", as `pdk build` writes it.

func init() {
	register(eco{
		ID: "puppet", Type: "puppet", Title: "Puppet Forge",
		Format:   "module release tarball (.tar.gz)",
		Registry: puppetRegistry,
	})
}

// puppetOwner is the Forge user every fixture module is published by. Owners
// are lower-case letters and digits, module names a lower-case letter followed
// by letters, digits and underscores: the variant's slug is a valid name.
const puppetOwner = "pte2e"

// puppetMD5 returns the hex MD5 of b, the legacy digest the Forge publishes
// next to the SHA-256.
func puppetMD5(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

// puppetModule builds the release tarball of a spec and returns it with the
// module's metadata.json, which the release document repeats.
func puppetModule(s pkgSpec, name, root string) (tarball []byte, metadata map[string]any) {
	metadata = map[string]any{
		"name": puppetOwner + "-" + name, "version": fixtureVersion, "author": puppetOwner,
		"summary": "pullthrough llm-package-scan e2e fixture", "license": "Apache-2.0",
		"dependencies": []any{},
		"requirements": []map[string]string{{"name": "puppet", "version_requirement": ">= 7.0.0 < 9.0.0"}},
	}
	tarball = tarGzOf(
		member{Name: root + "metadata.json", Data: string(jsonDoc(metadata))},
		member{Name: root + "README.md", Data: "# " + puppetOwner + "-" + name + "\n\npullthrough llm-package-scan e2e fixture.\n"},
		member{Name: root + "manifests/init.pp", Data: "# @summary Says hello.\nclass " + name + " {\n  notify { 'hello from the pkgscan e2e module': }\n}\n"},
		member{Name: root + markerFile, Data: s.Text("")},
	)
	return tarball, metadata
}

func puppetRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	for _, s := range env.Specs {
		name := s.Slug()
		module := puppetOwner + "-" + name // the coordinate: "<owner>-<name>"
		release := module + "-" + fixtureVersion
		tarball, metadata := puppetModule(s, name, release+"/")
		fileURI := "/v3/files/" + release + ".tar.gz"
		reg.mux.File(fileURI, tarball, "application/octet-stream")
		reg.mux.File("/v3/releases/"+release, jsonDoc(map[string]any{
			"uri": "/v3/releases/" + release, "slug": release,
			"module": map[string]any{
				"uri": "/v3/modules/" + module, "slug": module, "name": name, "deprecated_at": nil,
				"owner": map[string]string{"uri": "/v3/users/" + puppetOwner, "slug": puppetOwner, "username": puppetOwner},
			},
			"version": fixtureVersion, "metadata": metadata, "tags": []string{},
			"supported": false, "pdk": true, "validation_score": 100,
			"file_uri": fileURI, "file_size": len(tarball),
			"file_md5": puppetMD5(tarball), "file_sha256": hexOf(tarball),
			"downloads": 0, "created_at": "2024-01-02 03:04:05 -0800", "updated_at": "2024-01-02 03:04:05 -0800",
			"deleted_at": nil, "deleted_for": nil,
		}), "application/json")

		reg.add(s.Variant, &pkgPull{
			Name: module, Version: fixtureVersion,
			// The client takes file_uri (relative: resolved against the proxy mount)
			// and the digest it checks the download against from this document.
			Preamble: []step{{Path: "/v3/releases/" + release, Contains: []string{fileURI, hexOf(tarball)}}},
			Payload:  step{Path: fileURI},
			Body:     tarball,
			Marker:   release + "/" + markerFile,
		})
	}
	return reg, nil
}
