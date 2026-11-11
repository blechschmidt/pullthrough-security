package homebrew

import (
	"net/http"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about
// every path the Homebrew layout accepts. A bottle is the payload on both of
// its paths; the formula documents, the JSON API documents and the registry's
// manifests are metadata. Everything else under "/api/" is forwarded without
// being parsed, so it is left unclassified — never called metadata — and a gate
// judges it from its bytes.
func TestResolveArtifactClass(t *testing.T) {
	// Offline keeps Resolve free of network I/O for the registry-native bottle
	// path (no formula-API lookup); the fake upstreams below must stay untouched.
	env := newRegEnv(t, func(o *Options) { o.Offline = true })
	digest := hexOf("c")

	cases := []struct {
		path      string
		want      backends.ArtifactClass
		cacheable bool
	}{
		// Payloads: a bottle on the synthetic endpoint a rewritten formula
		// document points at.
		{"/bottle/wget/1.21.4/v2/homebrew/core/wget/blobs/sha256:" + digest, backends.ArtifactPayload, true},
		{"/bottle/openssl@3/3.2.1/v2/homebrew/core/openssl/3/blobs/sha256:" + digest, backends.ArtifactPayload, true},
		// Payloads: a bottle on the registry-native path the brew client builds
		// from HOMEBREW_ARTIFACT_DOMAIN — core tap, versioned formula, third-party
		// tap.
		{blobPath("homebrew/core/hello", digest), backends.ArtifactPayload, true},
		{blobPath("homebrew/core/openssl/3", digest), backends.ArtifactPayload, true},
		{blobPath("acme/tap/widget", digest), backends.ArtifactPayload, true},

		// Metadata: the unsigned formula index and a formula document.
		{"/api/formula.json", backends.ArtifactMetadata, false},
		{"/api/formula/wget.json", backends.ArtifactMetadata, false},
		{"/api/formula/openssl@3.json", backends.ArtifactMetadata, false},
		{"/api/formula/python@3.12.json", backends.ArtifactMetadata, false},
		{"/api/formula/gtk+3.json", backends.ArtifactMetadata, false},
		// Metadata: the other JSON API documents, proxied byte-exact.
		{"/api/formula.jws.json", backends.ArtifactMetadata, false},
		{"/api/cask.jws.json", backends.ArtifactMetadata, false},
		{"/api/formula_tap_migrations.jws.json", backends.ArtifactMetadata, false},
		{"/api/cask.json", backends.ArtifactMetadata, false},
		{"/api/cask/firefox.json", backends.ArtifactMetadata, false},
		{"/api/cask/visual-studio-code@insiders.json", backends.ArtifactMetadata, false},
		{"/api/formula/wget.jws.json", backends.ArtifactMetadata, false},
		{"/api/analytics/install/30d.json", backends.ArtifactMetadata, false},
		{"/api/internal/v3/homebrew-core.jws.json", backends.ArtifactMetadata, false},
		// Metadata: an OCI manifest or image index, by tag and by digest.
		{"/v2/homebrew/core/hello/manifests/2.12.3-1", backends.ArtifactMetadata, false},
		{"/v2/homebrew/core/openssl/3/manifests/3.5.9", backends.ArtifactMetadata, false},
		{"/v2/homebrew/core/hello/manifests/sha256:" + digest, backends.ArtifactMetadata, false},

		// Unclassified: "/api/..." paths that are forwarded but do not name a JSON
		// document. The prefix alone does not make them metadata: a file a client
		// evaluates, or an archive, served there must still be examined.
		{"/api/cask-source/firefox.rb", backends.ArtifactUnclassified, false},
		{"/api/formula-source/wget.rb", backends.ArtifactUnclassified, false},
		{"/api/formula_names.txt", backends.ArtifactUnclassified, false},
		{"/api/downloads/tool-1.0.tar.gz", backends.ArtifactUnclassified, false},
		{"/api/install.sh", backends.ArtifactUnclassified, false},
		{"/api/formula/wget", backends.ArtifactUnclassified, false},
		{"/api/formula.json.gz", backends.ArtifactUnclassified, false},
		{"/api", backends.ArtifactUnclassified, false},
		{"/api/", backends.ArtifactUnclassified, false},

		// Unclassified: a ".json" name on a path that is not spelled in plain
		// segments. A server that drops ";name=value" path parameters answers the
		// first three with whatever sits at the path without them — an archive, a
		// file outside "/api/" — so the name proves nothing; a formula document's
		// name is not exempt.
		{"/api/downloads/tool-1.0.tar.gz;.json", backends.ArtifactUnclassified, false},
		{"/api/..;/tools/tool-1.0.tar.gz;.json", backends.ArtifactUnclassified, false},
		{"/api/formula/tool-1.0.tar.gz;.json", backends.ArtifactUnclassified, false},
		{"/api/formula/wget;v=1.json", backends.ArtifactUnclassified, false},
		{"/api/cask;x/firefox.json", backends.ArtifactUnclassified, false},
		{"/api/cask/fire fox.json", backends.ArtifactUnclassified, false},
		{"/api/cask/firefox%2Fx.json", backends.ArtifactUnclassified, false},
		{"/api/cask\\firefox.json", backends.ArtifactUnclassified, false},
	}
	for _, c := range cases {
		res, err := resolveWith(t, env.backend, http.MethodGet, c.path, nil)
		if err != nil {
			t.Errorf("Resolve(%q): %v", c.path, err)
			continue
		}
		if res.Artifact.Class != c.want {
			t.Errorf("Resolve(%q).Artifact.Class = %s, want %s", c.path, res.Artifact.Class, c.want)
		}
		if res.Cacheable != c.cacheable {
			t.Errorf("Resolve(%q).Cacheable = %v, want %v", c.path, res.Cacheable, c.cacheable)
		}
		// A bottle is an OCI blob with no file name of its own, and the documents
		// are fetched from URLs ending in theirs: no explicit name is stated, and
		// no payload refinement.
		if res.Artifact.Filename != "" || res.Artifact.Kind != "" {
			t.Errorf("Resolve(%q).Artifact = %+v, want only a class", c.path, res.Artifact)
		}
	}

	if hits := env.apiRequests(); len(hits) != 0 {
		t.Errorf("offline Resolve asked the formula API for %v", hits)
	}
	if hits := env.registryRequests(); len(hits) != 0 {
		t.Errorf("Resolve contacted the bottle registry: %+v", hits)
	}
}

// TestRegistryBottleIsPayloadHoweverItsCoordinateIsFound checks the class of a
// registry-native bottle against each way its coordinate can be established —
// the image index the client fetched first, the formula API, and the digest
// stand-in when neither knows it. The coordinate is what varies; the bottle is
// a payload every time.
func TestRegistryBottleIsPayloadHoweverItsCoordinateIsFound(t *testing.T) {
	env := newRegEnv(t)
	fromManifest, fromAPI, unknown := hexOf("d"), hexOf("1"), hexOf("e")

	env.addManifest("homebrew/core/hello", "2.12.3-1",
		ociIndex("hello", "2.12.3", 1, platformBottle{"x86_64_linux", fromManifest}), ociIndexType)
	env.fetchManifest(t, "homebrew/core/hello", "2.12.3-1")
	env.addFormula("wget", formulaJSON("wget", "1.25.0", platformBottle{"x86_64_linux", fromAPI}))

	cases := []struct {
		path       string
		wantSource string
	}{
		{blobPath("homebrew/core/hello", fromManifest), versionSourceManifest},
		{blobPath("homebrew/core/wget", fromAPI), versionSourceFormulaAPI},
		{blobPath("homebrew/core/hello", unknown), versionSourceDigest},
	}
	for _, c := range cases {
		res := mustResolve(t, env.backend, c.path)
		if got := res.Metadata[MetaVersionSource]; got != c.wantSource {
			t.Errorf("Resolve(%q) version source = %q, want %q", c.path, got, c.wantSource)
		}
		if res.Artifact.Class != backends.ArtifactPayload {
			t.Errorf("Resolve(%q).Artifact.Class = %s, want payload", c.path, res.Artifact.Class)
		}
	}
}
