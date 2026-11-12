//go:build integration
// +build integration

package pkgscan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// Homebrew: formula metadata comes from the formulae API, and bottles — the
// prebuilt tarballs brew pours into its cellar — from an OCI registry (ghcr.io
// for homebrew/core) as content-addressed blobs. A formula document,
// "/api/formula/<name>.json", lists each bottle's blob URL and sha256; the
// proxy rewrites every URL on the configured bottle registry
// (`settings.bottleRegistryUrl`) onto its own bottle endpoint,
//
//	<proxy>/v1/<name>/bottle/<formula>/<version>/v2/<repo>/blobs/sha256:<hex>
//
// which carries the formula's name and version ahead of the blob path, and
// fetches the blob from the registry, verifying its sha256, when a client
// follows the link.
//
// The stub plays both upstreams. Its registry, like ghcr.io, serves a blob
// only to a bearer of a token: an anonymous request is answered 401 with a
// challenge naming the token endpoint and the repository scope, the token
// endpoint hands out a token for that scope, and the request is repeated with
// it — the handshake the backend performs on its own.
//
// A bottle is a gzip-compressed tar of "<formula>/<version>/…": the keg,
// with the receipt of the build and the formula's own source under .brew/.
//
// The proxy reports the formula name and version its bottle endpoint names.

func init() {
	register(eco{
		ID: "homebrew", Type: "homebrew", Title: "Homebrew",
		Format: "bottle (tar.gz, OCI blob behind a bearer token) via a rewritten formula document",
		// The stub is the bottle registry as well as the formulae API.
		Settings: func(stub string) map[string]string { return map[string]string{"bottleRegistryUrl": stub} },
		Registry: homebrewRegistry,
	})
}

// homebrewTap is the registry namespace of the core tap's bottles.
const homebrewTap = "homebrew/core"

func homebrewRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	host := strings.TrimPrefix(env.URL, "http://")

	// The token endpoint: an anonymous token for whatever repository scope is
	// asked for, as ghcr.io grants one for a public package.
	reg.mux.Handle("/token", func(w http.ResponseWriter, r *http.Request) {
		scope := r.URL.Query().Get("scope")
		if scope == "" || r.URL.Query().Get("service") != host {
			http.Error(w, `{"errors":[{"code":"DENIED","message":"scope and service required"}]}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonDoc(map[string]any{"token": homebrewToken(scope), "expires_in": 300}))
	})

	for _, s := range env.Specs {
		name := s.Name()
		keg := name + "/" + fixtureVersion + "/"
		bottle := tarGz(map[string]string{
			keg + "INSTALL_RECEIPT.json": string(jsonDoc(map[string]any{
				"homebrew_version": "4.4.0", "built_as_bottle": true, "poured_from_bottle": false,
				"runtime_dependencies": []any{}, "arch": "x86_64",
				"source": map[string]any{"tap": homebrewTap, "spec": "stable", "versions": map[string]any{"stable": fixtureVersion}},
			})),
			keg + ".brew/" + name + ".rb":            homebrewFormulaSource(name),
			keg + "share/" + name + "/" + markerFile: s.Text(""),
		})
		digest := hexOf(bottle)
		repo := homebrewTap + "/" + name // brew's image name is the formula name with "@" -> "/", "+" -> "x"
		blob := "/v2/" + repo + "/blobs/sha256:" + digest
		scope := "repository:" + repo + ":pull"
		reg.mux.Handle(blob, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+homebrewToken(scope) {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="%s",scope="%s"`, env.URL, host, scope))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`))
				return
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.layer.v1.tar+gzip")
			w.Header().Set("Docker-Content-Digest", "sha256:"+digest)
			http.ServeContent(w, r, "", stubModTime, bytes.NewReader(bottle))
		})

		// The formula document, in the shape formulae.brew.sh serves it (the
		// fields a client installs a bottle by). A bottle without compiled code is
		// poured on every platform: its one file is keyed "all".
		formula := "/api/formula/" + name + ".json"
		reg.mux.File(formula, jsonDoc(map[string]any{
			"name": name, "full_name": name, "tap": homebrewTap, "oldnames": []string{}, "aliases": []string{},
			"desc": "pullthrough llm-package-scan e2e fixture", "license": "MIT", "homepage": "https://example.invalid/pte2e",
			"versions": map[string]any{"stable": fixtureVersion, "head": nil, "bottle": true},
			"revision": 0, "version_scheme": 0,
			"bottle": map[string]any{"stable": map[string]any{
				"rebuild": 0, "root_url": env.URL + "/v2/" + homebrewTap,
				"files": map[string]any{"all": map[string]any{
					"cellar": ":any_skip_relocation", "url": env.URL + blob, "sha256": digest,
				}},
			}},
			"dependencies": []string{}, "build_dependencies": []string{},
		}), "application/json")

		proxied := "/bottle/" + name + "/" + fixtureVersion + blob
		reg.add(s.Variant, &pkgPull{
			Name: name, Version: fixtureVersion,
			// A consumer of the formula document downloads the bottle from the URL
			// the document gives: it must lead to the proxy's bottle endpoint.
			Preamble: []step{{Path: formula, Contains: []string{`"url": "` + mountPlaceholder + proxied + `"`, `"sha256": "` + digest + `"`}}},
			Payload:  step{Path: proxied},
			Body:     bottle,
			Marker:   keg + "share/" + name + "/" + markerFile,
		})
	}
	return reg, nil
}

// homebrewToken is the bearer token the stub registry issues for a scope.
func homebrewToken(scope string) string {
	sum := sha256.Sum256([]byte("pkgscan-e2e registry token\x00" + scope))
	return "pte2e." + hex.EncodeToString(sum[:16])
}

// homebrewFormulaSource is the formula a bottle carries under .brew/: the Ruby
// class brew evaluates, named after the formula ("pte2e-benign" -> Pte2eBenign).
func homebrewFormulaSource(name string) string {
	var class strings.Builder
	for _, part := range strings.Split(name, "-") {
		if part != "" {
			class.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	return "class " + class.String() + " < Formula\n" +
		"  desc \"pullthrough llm-package-scan e2e fixture\"\n" +
		"  homepage \"https://example.invalid/pte2e\"\n" +
		"  license \"MIT\"\n\n" +
		"  def install\n" +
		"    (share/\"" + name + "\").install \"" + markerFile + "\"\n" +
		"  end\n" +
		"end\n"
}
