//go:build fuzz
// +build fuzz

// Fuzz targets for the Homebrew pull-through parsers (Task 30, Task 158).
//
// A malicious or compromised upstream controls the formula JSON body and the
// OCI manifest body, and the client controls the request path. All are parsed
// on the pull path before any content is cached or served, so the parsers must
// never panic, must not allocate without bound, and must fail closed on
// malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/homebrew/
package homebrew

import (
	"strings"
	"testing"
)

func FuzzClassify(f *testing.F) {
	digest := strings.Repeat("a", 64)
	seeds := []string{
		"/api/formula.json",
		"/api/formula/wget.json",
		"/api/formula/openssl@3.json",
		"/api/cask.json",
		"/api/formula.jws.json",
		"/bottle/wget/1.21.4/v2/homebrew/core/wget/blobs/sha256:" + digest,
		"/bottle/wget/1.21.4/v2/homebrew/core/wget/blobs/sha256:short",
		"/bottle/wget", "/bottle//", "/api/../etc/passwd",
		"", "/", "////",
		// Registry-native paths, as the brew client builds them from
		// HOMEBREW_ARTIFACT_DOMAIN.
		"/v2/homebrew/core/hello/manifests/2.12.3-1",
		"/v2/homebrew/core/hello/manifests/sha256:" + digest,
		"/v2/homebrew/core/hello/blobs/sha256:" + digest,
		"/v2/homebrew/core/hello/blobs/sha256:" + strings.ToUpper(digest),
		"/v2/homebrew/core/openssl/3/blobs/sha256:" + digest,
		"/v2/homebrew/core/python/3.12/manifests/3.12.16",
		"/v2/acme/tap/widget/manifests/1.0.0",
		"/v2/", "/v2/_catalog", "/v2/homebrew/core/hello/tags/list",
		"/v2/library/alpine/manifests/latest",
		"/v2/homebrew/core/a/b/c/blobs/sha256:" + digest,
		"/v2/homebrew/core/Hello/manifests/1.0",
		"/v2/homebrew/core/he%2fllo/manifests/1.0",
		"/v2/homebrew/core/../../x/manifests/1.0",
		"/v2/homebrew/core/hello/manifests/a:b",
		"/v2/homebrew/core/hello/manifests/-x",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		res, ok := classify(path)
		if !ok {
			return
		}
		_ = res.cacheable()
		_ = res.kindLabel()
		_ = res.rewrites()
		if res.isBottle() {
			if len(res.digest) != sha256HexLen || !isHex(res.digest) {
				t.Fatalf("bottle resource with non-sha256 digest: %q -> %q", path, res.digest)
			}
			if res.repo == "" || res.name == "" {
				t.Fatalf("bottle resource with empty field: %q -> %+v", path, res)
			}
			// Only the registry-native path leaves the version to be resolved.
			if res.version == "" && !res.registryNative {
				t.Fatalf("synthetic bottle resource with no version: %q -> %+v", path, res)
			}
			if !strings.HasPrefix(res.blobPath, "v2/") {
				t.Fatalf("bottle blobPath not an OCI path: %q -> %q", path, res.blobPath)
			}
		}
		if res.registryNative {
			// Every component of a registry-native resource is joined into the
			// upstream URL and token scope, so it must be inert.
			segs := strings.Split(res.repo, "/")
			if !validRepo(segs) {
				t.Fatalf("registry-native resource with an invalid repository: %q -> %q", path, res.repo)
			}
			if strings.ContainsAny(res.repo+res.reference+res.blobPath, "%?#\\ \t\r\n") {
				t.Fatalf("registry-native resource carries a URL metacharacter: %q -> %+v", path, res)
			}
			if res.name == "" {
				t.Fatalf("registry-native resource with no formula name: %q -> %+v", path, res)
			}
			switch res.kind {
			case kindManifest:
				if _, ok := parseManifestReference(res.reference); !ok {
					t.Fatalf("manifest resource with an invalid reference: %q -> %q", path, res.reference)
				}
			case kindBottle:
				if res.blobPath != "v2/"+res.repo+"/blobs/sha256:"+res.digest {
					t.Fatalf("bottle blobPath is not canonical: %q -> %q", path, res.blobPath)
				}
			default:
				t.Fatalf("registry-native resource of kind %s: %q", res.kindLabel(), path)
			}
		}
	})
}

func FuzzRewriteBottleURLs(f *testing.F) {
	digest := strings.Repeat("c", 64)
	f.Add([]byte(`{"name":"wget","versions":{"stable":"1.0"},"bottle":{"stable":{"files":{"x":{"url":"https://ghcr.io/v2/homebrew/core/wget/blobs/sha256:` + digest + `","sha256":"` + digest + `"}}}}}`))
	f.Add([]byte(`[{"name":"a","versions":{"stable":"1"}},{"name":"b"}]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, body []byte) {
		out, n := rewriteBottleURLs(body, "https://proxy.example/v1/homebrew", "ghcr.io")
		if n < 0 {
			t.Fatalf("negative rewrite count")
		}
		// A document that was not rewritten must be returned byte-for-byte.
		if n == 0 && string(out) != string(body) {
			t.Fatalf("no-op rewrite altered the body")
		}
	})
}

// FuzzParseBottleManifest drives the OCI manifest parser the backend runs over
// every manifest it proxies. Whatever the registry returns, parsing must not
// panic, must respect the per-document bound, and may only ever yield a
// well-formed digest and version — those become the coordinate the admission
// gates see.
func FuzzParseBottleManifest(f *testing.F) {
	digest := strings.Repeat("d", 64)
	f.Add(ociIndex("hello", "2.12.3", 1, platformBottle{"x86_64_linux", digest}, platformBottle{"arm64_sequoia", strings.Repeat("e", 64)}))
	f.Add(ociIndex("gtk+3", "3.24.52_1", 0, platformBottle{"all", digest}))
	f.Add(ociIndex("imagemagick", "7.1.2-35", 0, platformBottle{"arm64_golden_gate", digest}))
	f.Add([]byte(`{"schemaVersion":2,"layers":[{"digest":"sha256:` + digest + `"}],"annotations":{"org.opencontainers.image.title":"hello 2.12.3.x86_64_linux.1","org.opencontainers.image.version":"2.12.3","org.opencontainers.image.ref.name":"2.12.3.x86_64_linux.1","sh.brew.bottle.digest":"` + digest + `"}}`))
	f.Add([]byte(`{"manifests":[{"annotations":{"org.opencontainers.image.ref.name":"1/0.sonoma","sh.brew.bottle.digest":"` + digest + `"}}]}`))
	f.Add([]byte(`{"manifests":[{"annotations":{"sh.brew.bottle.digest":42,"org.opencontainers.image.ref.name":null}}],"annotations":"x"}`))
	f.Add([]byte(`{"annotations":{"org.opencontainers.image.version":"_1","sh.brew.bottle.digest":"` + digest + `"}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, body []byte) {
		facts, ok := parseBottleManifest(body)
		if ok != (len(facts.bottles) > 0) {
			t.Fatalf("ok=%v with %d bottles", ok, len(facts.bottles))
		}
		if len(facts.bottles) > maxBottlesPerManifest {
			t.Fatalf("learned %d bottles, above the bound %d", len(facts.bottles), maxBottlesPerManifest)
		}
		for _, b := range facts.bottles {
			if len(b.digest) != sha256HexLen || !isHex(b.digest) || b.digest != strings.ToLower(b.digest) {
				t.Fatalf("learned a malformed digest %q", b.digest)
			}
			if !validVersion(b.version) {
				t.Fatalf("learned an invalid version %q", b.version)
			}
		}
		// The title is only ever used after validation against a repository; a
		// name it yields must map back to that repository's image.
		if name, ok := formulaNameFromTitle(coreTap, "hello", facts.title); ok && imageFormulaName(name) != "hello" {
			t.Fatalf("title %q validated to %q for image hello", facts.title, name)
		}
	})
}

// FuzzFormulaVersion drives the reference-name splitter with arbitrary
// annotation values: the derived version is either rejected or a valid OCI tag
// (never empty, never over-long, never carrying a path separator or the ":" of
// the digest-derived fallback version).
func FuzzFormulaVersion(f *testing.F) {
	for _, seed := range [][2]string{
		{"2.12.3.x86_64_linux.1", "2.12.3"},
		{"1.92.0_1.arm64_sequoia", "1.92.0_1"},
		{"7.1.2-35.all", ""},
		{"1.0.rc1.sonoma", "9.9"},
		{"", "3.5.9_2"},
		{"garbage", ""},
		{"...", "_"},
		{"1/2.sonoma", "a b"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, refName, pkgVersion string) {
		version, ok := formulaVersion(refName, pkgVersion)
		if !ok {
			if version != "" {
				t.Fatalf("rejected input yielded version %q", version)
			}
			return
		}
		if !validVersion(version) {
			t.Fatalf("formulaVersion(%q, %q) = %q, not a valid version", refName, pkgVersion, version)
		}
		if strings.HasPrefix(version, "sha256:") {
			t.Fatalf("a derived version collides with the digest fallback namespace: %q", version)
		}
	})
}
