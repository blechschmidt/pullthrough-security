//go:build integration
// +build integration

package pkgscan

// Open VSX: a client (`ovsx get`, an editor using the registry as its gallery)
// reads an extension version's metadata, "/api/<namespace>/<extension>/<version>",
// whose `files` name the archive and its checksum by absolute URL — the proxy
// rewrites the registry's own URLs onto itself — and downloads the .vsix from
// "/api/…/file/<namespace>.<extension>-<version>.vsix". The backend verifies
// the archive against the registry's sibling ".sha256" file. A .vsix is a zip
// holding the VSIX manifest and, under "extension/", the extension as
// published.

func init() {
	register(eco{
		ID: "openvsx", Type: "openvsx", Title: "Open VSX (VS Code extensions)",
		Format:   "extension archive (.vsix, zip)",
		Registry: openvsxRegistry,
	})
}

// openvsxNamespace is the publisher every fixture extension is published under.
const openvsxNamespace = "pte2e"

// vsixBuild builds the .vsix of a spec, members in the order `vsce package`
// writes them. The extension activates on its own command only: no lifecycle
// script and no wildcard activation, either of which the install-hooks gate
// would hold against it.
func vsixBuild(s pkgSpec, extension string) []byte {
	manifest := jsonDoc(map[string]any{
		"name": extension, "publisher": openvsxNamespace, "version": fixtureVersion,
		"displayName": "PTE2E " + string(s.Variant), "description": "pullthrough llm-package-scan e2e fixture",
		"engines": map[string]string{"vscode": "^1.80.0"}, "categories": []string{"Other"},
		"main":             "./extension.js",
		"activationEvents": []string{"onCommand:" + openvsxNamespace + "." + extension + ".hello"},
		"contributes": map[string]any{"commands": []map[string]string{
			{"command": openvsxNamespace + "." + extension + ".hello", "title": "PTE2E: Hello"},
		}},
	})
	return zipOf(
		member{Name: "extension.vsixmanifest", Data: `<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="` + extension + `" Version="` + fixtureVersion + `" Publisher="` + openvsxNamespace + `" />
    <DisplayName>PTE2E ` + string(s.Variant) + `</DisplayName>
    <Description xml:space="preserve">pullthrough llm-package-scan e2e fixture</Description>
    <Categories>Other</Categories>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="^1.80.0" />
    </Properties>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code"/>
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />
  </Assets>
</PackageManifest>
`},
		member{Name: "[Content_Types].xml", Data: `<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension=".json" ContentType="application/json"/><Default Extension=".js" ContentType="application/javascript"/><Default Extension=".txt" ContentType="text/plain"/><Default Extension=".vsixmanifest" ContentType="text/xml"/></Types>
`},
		member{Name: "extension/package.json", Data: string(manifest)},
		member{Name: "extension/extension.js", Data: "exports.activate = function () {};\nexports.deactivate = function () {};\n"},
		member{Name: "extension/" + markerFile, Data: s.Text("")},
	)
}

func openvsxRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	for _, s := range env.Specs {
		extension := s.Slug()
		id := openvsxNamespace + "." + extension // the coordinate: "<namespace>.<extension>"
		version := "/api/" + openvsxNamespace + "/" + extension + "/" + fixtureVersion
		files := version + "/file/"
		vsix := vsixBuild(s, extension)
		archive := files + id + "-" + fixtureVersion + ".vsix"
		sidecar := files + id + "-" + fixtureVersion + ".sha256"
		reg.mux.File(archive, vsix, "application/octet-stream")
		// The registry publishes the archive's SHA-256 as a bare hex string.
		reg.mux.File(sidecar, []byte(hexOf(vsix)), "text/plain")
		reg.mux.File(version, jsonDoc(map[string]any{
			"namespaceUrl": env.URL + "/api/" + openvsxNamespace,
			"reviewsUrl":   env.URL + "/api/" + openvsxNamespace + "/" + extension + "/reviews",
			"files": map[string]string{
				"download": env.URL + archive,
				"sha256":   env.URL + sidecar,
				"manifest": env.URL + files + "package.json",
			},
			"name": extension, "namespace": openvsxNamespace, "version": fixtureVersion,
			"targetPlatform": "universal", "timestamp": "2024-01-02T03:04:05.000000Z",
			"displayName": "PTE2E " + string(s.Variant), "description": "pullthrough llm-package-scan e2e fixture",
			"engines": map[string]string{"vscode": "^1.80.0"}, "verified": false,
		}), "application/json")

		reg.add(s.Variant, &pkgPull{
			Name: id, Version: fixtureVersion,
			// `ovsx get` reads the version's metadata and downloads files.download,
			// which must lead back to the proxy — and so must the checksum it names.
			Preamble: []step{{Path: version, Contains: []string{mountPlaceholder + archive, mountPlaceholder + sidecar}}},
			Payload:  step{Path: archive},
			Body:     vsix,
			Marker:   "extension/" + markerFile,
		})
	}
	return reg, nil
}
