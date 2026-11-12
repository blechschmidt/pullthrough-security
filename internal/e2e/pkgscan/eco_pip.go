//go:build integration
// +build integration

package pkgscan

import (
	"fmt"
	"strings"
)

// PyPI: the Simple API page of a project links its distribution files by
// absolute URL on a separate file host. The proxy rewrites those links onto its
// files route ("/files/<scheme>/<host>/<path>"), which is where a distribution
// is a payload. The package pulled here is a wheel: a zip.

func init() {
	register(eco{
		ID: "pip", Type: "pip", Title: "PyPI (pip)",
		Format: "wheel (.whl, zip)",
		// The stub plays the file host too; naming it as filesUrl puts it on the
		// allowlist of hosts the files route may fetch from.
		Settings: func(stub string) map[string]string { return map[string]string{"filesUrl": stub} },
		Registry: pipRegistry,
	})
}

func pipRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	scheme, host, ok := strings.Cut(env.URL, "://")
	if !ok {
		return nil, fmt.Errorf("unexpected stub URL %q", env.URL)
	}
	for _, s := range env.Specs {
		project := s.Name()                           // pte2e-benign (PEP 503 normalized)
		dist := strings.ReplaceAll(project, "-", "_") // pte2e_benign (the importable name)
		file := dist + "-" + fixtureVersion + "-py3-none-any.whl"
		info := dist + "-" + fixtureVersion + ".dist-info/"
		wheel := zipFiles(map[string]string{
			dist + "/__init__.py":   "VERSION = \"" + fixtureVersion + "\"\n",
			dist + "/" + markerFile: s.Text(""),
			info + "METADATA":       "Metadata-Version: 2.1\nName: " + project + "\nVersion: " + fixtureVersion + "\n",
			info + "WHEEL":          "Wheel-Version: 1.0\nGenerator: pkgscan-e2e\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
			info + "RECORD":         dist + "/__init__.py,,\n",
			info + "top_level.txt":  dist + "\n",
		})
		filePath := "/packages/" + file
		reg.mux.File(filePath, wheel, "application/octet-stream")
		reg.mux.File("/simple/"+project+"/", []byte(fmt.Sprintf(
			"<!DOCTYPE html>\n<html><head><meta name=\"pypi:repository-version\" content=\"1.0\"><title>Links for %s</title></head>\n"+
				"<body><h1>Links for %s</h1>\n<a href=\"%s%s#sha256=%s\">%s</a><br/>\n</body></html>\n",
			project, project, env.URL, filePath, hexOf(wheel), file)), "text/html")

		proxied := "/files/" + scheme + "/" + host + filePath
		reg.add(s.Variant, &pkgPull{
			Name: project, Version: fixtureVersion,
			// pip follows the link on the project page: it must lead to the proxy's
			// files route, not to the file host.
			Preamble: []step{{Path: "/simple/" + project + "/", Contains: []string{mountPlaceholder + proxied + "#sha256=" + hexOf(wheel)}}},
			Payload:  step{Path: proxied},
			Body:     wheel,
			Marker:   dist + "/" + markerFile,
		})
	}
	return reg, nil
}
