//go:build integration
// +build integration

package pkgscan

import "strings"

// JSR: a package "@<scope>/<name>" is served one module file at a time; there
// is no archive. Deno reads the package's "meta.json" (its versions), then the
// version's "<version>_meta.json", whose "manifest" maps every file of the
// version to its size and "sha256-<hex>" checksum, then fetches the module
// files it imports from "/@<scope>/<name>/<version>/<path>". On a miss the proxy
// looks the file up in the version manifest and verifies it before serving it.
//
// The payload is therefore a single TypeScript module, which the scanner lists
// under its file name; the variant's text is in it behind a comment leader,
// after the module's header.

func init() {
	register(eco{
		ID: "jsr", Type: "jsr", Title: "JSR",
		Format:   "module file (.ts), served singly",
		Registry: jsrRegistry,
	})
}

// jsrScope is the scope every fixture is published under.
const jsrScope = "pte2e"

// jsrModuleHeader is what the fixture module holds in front of the variant's
// text.
const jsrModuleHeader = "// Copyright 2024 the pkgscan e2e authors. MIT license.\n" +
	"/**\n" +
	" * A fixture module of the LLM package-scan e2e suite.\n" +
	" * @module\n" +
	" */\n"

func jsrRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	for _, s := range env.Specs {
		name := s.Slug() // JSR names: lower-case letters, digits and '-'
		pkg := "/@" + jsrScope + "/" + name
		module := []byte(jsrModuleHeader + s.Text("// ") + "export function answer(): number {\n  return 42;\n}\n")
		config := jsonDoc(map[string]any{"name": "@" + jsrScope + "/" + name, "version": fixtureVersion, "exports": "./mod.ts"})
		files := map[string][]byte{"/mod.ts": module, "/jsr.json": config}

		manifest := map[string]any{}
		for path, body := range files {
			manifest[path] = map[string]any{"size": len(body), "checksum": "sha256-" + hexOf(body)}
			reg.mux.File(pkg+"/"+fixtureVersion+path, body, jsrContentType(path))
		}
		reg.mux.File(pkg+"/meta.json", jsonDoc(map[string]any{
			"scope":    jsrScope,
			"name":     name,
			"latest":   fixtureVersion,
			"versions": map[string]any{fixtureVersion: map[string]any{}},
		}), "application/json")
		versionMeta := pkg + "/" + fixtureVersion + "_meta.json"
		reg.mux.File(versionMeta, jsonDoc(map[string]any{
			"manifest":     manifest,
			"moduleGraph2": map[string]any{"/mod.ts": map[string]any{}},
			"exports":      map[string]string{".": "./mod.ts"},
		}), "application/json")

		reg.add(s.Variant, &pkgPull{
			Name: "@" + jsrScope + "/" + name, Version: fixtureVersion,
			Preamble: []step{
				{Path: pkg + "/meta.json", Contains: []string{fixtureVersion}},
				// What Deno checks the module against: the checksum the registry
				// published for it.
				{Path: versionMeta, Contains: []string{"sha256-" + hexOf(module)}},
			},
			Payload:      step{Path: pkg + "/" + fixtureVersion + "/mod.ts"},
			Body:         module,
			Marker:       "mod.ts",
			MarkerOffset: strings.Count(jsrModuleHeader, "\n"),
		})
	}
	return reg, nil
}

// jsrContentType is the media type JSR serves a module file with.
func jsrContentType(path string) string {
	switch {
	case strings.HasSuffix(path, ".ts"):
		return "application/typescript; charset=utf-8"
	case strings.HasSuffix(path, ".json"):
		return "application/json"
	default:
		return "application/octet-stream"
	}
}
