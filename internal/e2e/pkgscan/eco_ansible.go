//go:build integration
// +build integration

package pkgscan

// Ansible Galaxy (v3 API, as galaxy_ng serves it): `ansible-galaxy collection
// install <namespace>.<name>:<version>` discovers the API at "/api/", lists the
// collection's versions and reads the version's detail document, whose
// `download_url` names the collection artifact by absolute URL. The proxy
// rewrites every link those documents carry into the registry onto its mount:
// an absolute URL onto its public URL, a root-relative one ("href") onto the
// mount's path. The artifact, "…/collections/artifacts/<namespace>-<name>-
// <version>.tar.gz", is verified against the `artifact.sha256` of the same
// detail document, which the backend fetches itself. A collection artifact is a
// gzip-compressed tar with MANIFEST.json and FILES.json at its root, as
// `ansible-galaxy collection build` writes it.

func init() {
	register(eco{
		ID: "ansible", Type: "ansible", Title: "Ansible Galaxy",
		Format:   "collection artifact (.tar.gz)",
		Registry: ansibleRegistry,
	})
}

const (
	// ansibleNamespace is the namespace every fixture collection is published
	// under. Galaxy names are lower-case letters, digits and underscores: the
	// variant's slug is a valid collection name.
	ansibleNamespace = "pte2e"
	// ansibleContent is the canonical collections tree of the "published"
	// repository.
	ansibleContent = "/api/v3/plugin/ansible/content/published/collections"
	// ansibleMountPath is the path of the upstream's mount on the proxy
	// ("/v1/<ID>"), which a root-relative link is rewritten to carry.
	ansibleMountPath = "/v1/ansible"
)

// ansibleCollection builds the collection artifact of a spec: MANIFEST.json
// (naming FILES.json and its digest), FILES.json (every file with its digest)
// and the collection's files, at the root of the tarball.
func ansibleCollection(s pkgSpec, name string) []byte {
	files := []member{
		{Name: "README.md", Data: "# " + ansibleNamespace + "." + name + "\n\npullthrough llm-package-scan e2e fixture.\n"},
		{Name: "meta/runtime.yml", Data: "requires_ansible: '>=2.14.0'\n"},
		{Name: "plugins/modules/hello.py", Data: "#!/usr/bin/python\n# -*- coding: utf-8 -*-\n" +
			"DOCUMENTATION = r'''\nmodule: hello\nshort_description: Returns a greeting.\n'''\n\n" +
			"from ansible.module_utils.basic import AnsibleModule\n\n\ndef main():\n" +
			"    module = AnsibleModule(argument_spec={})\n    module.exit_json(changed=False, msg='hello')\n\n\n" +
			"if __name__ == '__main__':\n    main()\n"},
		{Name: markerFile, Data: s.Text("")},
	}
	entries := []map[string]any{{"name": ".", "ftype": "dir", "chksum_type": nil, "chksum_sha256": nil, "format": 1}}
	for _, dir := range []string{"meta", "plugins", "plugins/modules"} {
		entries = append(entries, map[string]any{"name": dir, "ftype": "dir", "chksum_type": nil, "chksum_sha256": nil, "format": 1})
	}
	for _, f := range files {
		entries = append(entries, map[string]any{"name": f.Name, "ftype": "file", "chksum_type": "sha256", "chksum_sha256": hexOf([]byte(f.Data)), "format": 1})
	}
	filesJSON := jsonDoc(map[string]any{"files": entries, "format": 1})
	manifest := jsonDoc(map[string]any{
		"collection_info": map[string]any{
			"namespace": ansibleNamespace, "name": name, "version": fixtureVersion,
			"authors": []string{"pullthrough"}, "readme": "README.md", "tags": []string{},
			"description": "pullthrough llm-package-scan e2e fixture", "license": []string{"MIT"},
			"dependencies": map[string]string{},
		},
		"file_manifest_file": map[string]any{
			"name": "FILES.json", "ftype": "file", "chksum_type": "sha256", "chksum_sha256": hexOf(filesJSON), "format": 1,
		},
		"format": 1,
	})
	return tarGzOf(append([]member{{Name: "MANIFEST.json", Data: string(manifest)}, {Name: "FILES.json", Data: string(filesJSON)}}, files...)...)
}

func ansibleRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	// The API root: which API versions the server speaks, relative to "/api/".
	reg.mux.File("/api/", jsonDoc(map[string]any{
		"available_versions": map[string]string{"v3": "v3/", "pulp-v3": "pulp/api/v3/"},
		"server_version":     "4.10.0", "galaxy_ng_version": "4.10.0",
	}), "application/json")
	for _, s := range env.Specs {
		name := s.Slug()
		artifact := ansibleCollection(s, name)
		file := ansibleNamespace + "-" + name + "-" + fixtureVersion + ".tar.gz"
		download := ansibleContent + "/artifacts/" + file
		collection := ansibleContent + "/index/" + ansibleNamespace + "/" + name + "/"
		versions := collection + "versions/"
		detail := versions + fixtureVersion + "/"
		reg.mux.File(download, artifact, "application/gzip")
		reg.mux.File(versions, jsonDoc(map[string]any{
			"meta": map[string]int{"count": 1},
			"links": map[string]any{
				"first": versions + "?limit=100&offset=0", "previous": nil, "next": nil,
				"last": versions + "?limit=100&offset=0",
			},
			"data": []map[string]any{{
				"version": fixtureVersion, "href": detail, "created_at": "2024-01-02T03:04:05.000000Z",
				"updated_at": "2024-01-02T03:04:05.000000Z", "requires_ansible": ">=2.14.0", "marks": []string{},
			}},
		}), "application/json")
		reg.mux.File(detail, jsonDoc(map[string]any{
			"version": fixtureVersion, "href": detail, "download_url": env.URL + download,
			"artifact":   map[string]any{"filename": file, "sha256": hexOf(artifact), "size": len(artifact)},
			"collection": map[string]any{"name": name, "href": collection},
			"namespace":  map[string]any{"name": ansibleNamespace},
			"name":       name, "requires_ansible": ">=2.14.0", "signatures": []string{},
			"created_at": "2024-01-02T03:04:05.000000Z", "updated_at": "2024-01-02T03:04:05.000000Z",
			"metadata": map[string]any{
				"authors": []string{"pullthrough"}, "description": "pullthrough llm-package-scan e2e fixture",
				"license": []string{"MIT"}, "tags": []string{}, "dependencies": map[string]string{},
			},
		}), "application/json")

		reg.add(s.Variant, &pkgPull{
			// The coordinate is the collection's fully-qualified name.
			Name: ansibleNamespace + "." + name, Version: fixtureVersion,
			Preamble: []step{
				{Path: "/api/", Contains: []string{`"v3/"`}},
				// The version's href, followed to its detail, stays inside the mount.
				{Path: versions + "?limit=100", Contains: []string{`"` + ansibleMountPath + detail + `"`}},
				// download_url must lead back to the proxy.
				{Path: detail, Contains: []string{mountPlaceholder + download, hexOf(artifact)}},
			},
			Payload: step{Path: download},
			Body:    artifact,
			Marker:  markerFile,
		})
	}
	return reg, nil
}
