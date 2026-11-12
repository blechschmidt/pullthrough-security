//go:build integration
// +build integration

package pkgscan

import "net/http"

// Dart / Flutter pub (Hosted Pub Repository API v2). `dart pub get` asks for a
// package's version listing, "/api/packages/<name>", in which every release
// names its archive by absolute "archive_url" — on pub.dev a URL that redirects
// to a storage bucket — together with the archive's "archive_sha256". The proxy
// rewrites each "archive_url" onto its own "/api/archives/<name>-<version>.tar.gz"
// endpoint; on a miss that endpoint re-reads the listing from the registry,
// fetches the archive from the URL it names and verifies it against
// "archive_sha256" before serving it. A pub archive is a gzip-compressed tar
// whose members sit at the package root.
//
// "pub" is a configuration alias of the type: the same registry, served by the
// proxy under the alias, is a row of its own.

func init() {
	dart := eco{
		ID: "dart", Type: "dart", Title: "Dart / Flutter (pub)",
		Format:   "package archive (.tar.gz)",
		Registry: dartRegistry,
	}
	register(dart)
	register(alias(dart, "pub"))
}

// dartAccept is the media type `dart pub` asks a hosted repository for, and
// the one the repository answers with.
const dartAccept = "application/vnd.pub.v2+json"

// The pubspec fields every fixture package shares.
const (
	dartDescription = "pkgscan e2e fixture package."
	dartSDK         = ">=3.0.0 <4.0.0"
)

func dartRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	for _, s := range env.Specs {
		name := "pte2e_" + s.Slug() // pub names: lower-case letters, digits and '_'
		// The listing carries each release's pubspec as JSON; the archive holds it
		// as pubspec.yaml.
		pubspec := map[string]any{
			"name":        name,
			"version":     fixtureVersion,
			"description": dartDescription,
			"environment": map[string]string{"sdk": dartSDK},
		}
		archive := tarGz(map[string]string{
			"pubspec.yaml":          "name: " + name + "\nversion: " + fixtureVersion + "\ndescription: " + dartDescription + "\nenvironment:\n  sdk: '" + dartSDK + "'\n",
			"lib/" + name + ".dart": "int answer() => 42;\n",
			markerFile:              s.Text(""),
		})
		// Where the archive really lives: the storage bucket pub.dev's own
		// archive URLs redirect to.
		bucket := "/storage/pub-packages/packages/" + name + "-" + fixtureVersion + ".tar.gz"
		reg.mux.File(bucket, archive, "application/octet-stream")
		entry := map[string]any{
			"version":        fixtureVersion,
			"pubspec":        pubspec,
			"archive_url":    env.URL + bucket,
			"archive_sha256": hexOf(archive),
			"published":      stubModTime.Format("2006-01-02T15:04:05.000Z07:00"),
		}
		listing := "/api/packages/" + name
		reg.mux.File(listing, jsonDoc(map[string]any{
			"name":     name,
			"latest":   entry,
			"versions": []any{entry},
		}), dartAccept)

		archivePath := "/api/archives/" + name + "-" + fixtureVersion + ".tar.gz"
		reg.add(s.Variant, &pkgPull{
			Name: name, Version: fixtureVersion,
			Preamble: []step{{
				Path:   listing,
				Header: http.Header{"Accept": {dartAccept}},
				// pub downloads from "archive_url" and checks "archive_sha256": the
				// first must be the proxy's endpoint, the second the registry's.
				Contains: []string{
					`"archive_url":"` + mountPlaceholder + archivePath + `"`,
					`"archive_sha256":"` + hexOf(archive) + `"`,
				},
			}},
			Payload: step{Path: archivePath},
			Body:    archive,
			Marker:  markerFile,
		})
	}
	return reg, nil
}
