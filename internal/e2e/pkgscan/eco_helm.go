//go:build integration
// +build integration

package pkgscan

import (
	"fmt"
	"strings"
)

// Helm, classic chart repository (`helm repo add`): index.yaml lists every
// chart version with the URL of its archive and the archive's SHA-256
// (`digest`). The proxy serves the index with every chart URL rewritten onto
// its own "/-/<chart>/<version>/<file>" route; an archive requested there is
// fetched from wherever the index lists it — here an absolute URL on the stub
// host, as a repository that publishes its archives as release assets has it —
// and verified against the index digest before it is cached. A chart archive
// is a gzip-compressed tar whose members sit under "<chart>/".
//
// The same chart, pushed to an OCI registry, is the helm-oci row.

func init() {
	register(eco{
		ID: "helm", Type: "helm", Title: "Helm (chart repository)",
		Format:   "chart archive (.tgz)",
		Registry: helmRegistry,
	})
}

// helmCreated is the creation time every fixture chart is published with.
const helmCreated = "2024-01-02T03:04:05Z"

// helmChart builds the chart archive of a spec the way `helm package` lays one
// out: Chart.yaml, values.yaml and the templates, under "<chart>/". It returns
// the chart's name and the archive.
func helmChart(s pkgSpec) (name string, archive []byte) {
	name = s.Name()
	root := name + "/"
	archive = tarGzOf(
		member{Name: root + "Chart.yaml", Data: "apiVersion: v2\nname: " + name + "\ndescription: pullthrough llm-package-scan e2e fixture\n" +
			"type: application\nversion: " + fixtureVersion + "\nappVersion: \"" + fixtureVersion + "\"\n"},
		member{Name: root + "values.yaml", Data: "greeting: hello\n"},
		member{Name: root + "templates/configmap.yaml", Data: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n" +
			"  name: {{ .Release.Name }}-pte2e\ndata:\n  greeting: {{ .Values.greeting | quote }}\n"},
		member{Name: root + markerFile, Data: s.Text("")},
	)
	return name, archive
}

func helmRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	// One index lists every chart, in the shape `helm repo index` writes.
	var index strings.Builder
	index.WriteString("apiVersion: v1\nentries:\n")
	for _, s := range env.Specs {
		name, archive := helmChart(s)
		file := name + "-" + fixtureVersion + ".tgz"
		upstream := "/charts/" + file
		reg.mux.File(upstream, archive, "application/gzip")
		fmt.Fprintf(&index, "  %s:\n  - apiVersion: v2\n    appVersion: %s\n    created: %q\n"+
			"    description: pullthrough llm-package-scan e2e fixture\n    digest: %s\n    name: %s\n"+
			"    type: application\n    urls:\n    - %s\n    version: %s\n",
			name, fixtureVersion, helmCreated, hexOf(archive), name, env.URL+upstream, fixtureVersion)

		// The index-resolved route names the chart and version as the index has
		// them, and the archive's file name; that is the coordinate the proxy
		// reports.
		proxied := "/-/" + name + "/" + fixtureVersion + "/" + file
		reg.add(s.Variant, &pkgPull{
			Name: name, Version: fixtureVersion,
			// `helm repo update` fetches the index; `helm pull` downloads the URL it
			// lists for the version, which the proxy must have pointed at itself.
			Preamble: []step{{Path: "/index.yaml", Contains: []string{mountPlaceholder + proxied}}},
			Payload:  step{Path: proxied},
			Body:     archive,
			Marker:   name + "/" + markerFile,
		})
	}
	fmt.Fprintf(&index, "generated: %q\n", helmCreated)
	reg.mux.File("/index.yaml", []byte(index.String()), "application/x-yaml")
	return reg, nil
}
