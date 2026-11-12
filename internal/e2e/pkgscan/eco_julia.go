//go:build integration
// +build integration

package pkgscan

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Julia Pkg Server protocol: everything but the registry list is content
// addressed. Pkg asks "/registries" for the current tree hash of each registry
// it uses, downloads that registry, "/registry/<uuid>/<tree hash>" — a tar.gz
// of TOML files in which every package's Versions.toml names each version's
// "git-tree-sha1" — and then the package itself, "/package/<uuid>/<tree hash>":
// a tar.gz of the package's source tree. The tree hash is the SHA-1 of the Git
// tree object of the unpacked tarball; the proxy recomputes it from the bytes
// and refuses a tarball that does not hash to its URL, so the stub serves real
// tree hashes (juliaTreeHash).
//
// The protocol names neither a package nor a version: the coordinate the proxy
// reports for a package tarball is the package's UUID and the tree hash.

func init() {
	register(eco{
		ID: "julia", Type: "julia", Title: "Julia (Pkg server)",
		Format:   "package tarball (.tar.gz, by tree hash)",
		Registry: juliaRegistry,
	})
}

func juliaRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	var (
		pulls         []*pkgPull
		registryFiles []member
		packagesTable strings.Builder
	)
	for _, s := range env.Specs {
		name := "Pte2e" + strings.ToUpper(s.Slug()[:1]) + s.Slug()[1:] // a Julia identifier: Pte2eBenign
		uuid := juliaUUID(name)
		tree := []member{
			{Name: "Project.toml", Data: "name = \"" + name + "\"\nuuid = \"" + uuid + "\"\nversion = \"" + fixtureVersion + "\"\n"},
			{Name: "src/" + name + ".jl", Data: "module " + name + "\n\nanswer() = 42\n\nend # module\n"},
			{Name: markerFile, Data: s.Text("")},
		}
		hash := juliaTreeHash(tree)
		tarball := tarGzOf(tree...)
		path := "/package/" + uuid + "/" + hash
		reg.mux.File(path, tarball, "application/gzip")
		pull := &pkgPull{
			Name: uuid, Version: hash,
			Payload: step{Path: path},
			Body:    tarball,
			Marker:  markerFile,
		}
		reg.add(s.Variant, pull)
		pulls = append(pulls, pull)

		// The package's entry in the registry, laid out as in General: the
		// package's directory under its initial, holding its identity and the tree
		// hash of every version.
		dir := "P/" + name + "/"
		registryFiles = append(registryFiles,
			member{Name: dir + "Package.toml", Data: "name = \"" + name + "\"\nuuid = \"" + uuid + "\"\nrepo = \"https://example.invalid/pte2e/" + name + ".jl.git\"\n"},
			member{Name: dir + "Versions.toml", Data: "[\"" + fixtureVersion + "\"]\ngit-tree-sha1 = \"" + hash + "\"\n"},
		)
		fmt.Fprintf(&packagesTable, "%s = { name = %q, path = %q }\n", uuid, name, "P/"+name)
	}
	registryUUID := juliaUUID("registry")
	registryFiles = append(registryFiles, member{Name: "Registry.toml", Data: "name = \"PTE2E\"\nuuid = \"" + registryUUID + "\"\n" +
		"repo = \"https://example.invalid/pte2e/PTE2ERegistry.git\"\n" +
		"description = \"The registry of the pkgscan e2e fixture packages.\"\n\n[packages]\n" + packagesTable.String()})
	registryPath := "/registry/" + registryUUID + "/" + juliaTreeHash(registryFiles)
	reg.mux.File("/registries", []byte(registryPath+"\n"), "text/plain; charset=utf-8")
	reg.mux.File(registryPath, tarGzOf(registryFiles...), "application/gzip")

	for _, pull := range pulls {
		pull.Preamble = []step{
			{Path: "/registries", Contains: []string{registryPath}},
			// The registry is an index that is an archive: served, never examined
			// as a package, under every fail mode.
			{Path: registryPath},
		}
	}
	return reg, nil
}

// juliaUUID derives a stable UUID (version 5 layout) for a fixture name, so
// every run publishes the same packages under the same identifiers.
func juliaUUID(name string) string {
	sum := sha1.Sum([]byte("pullthrough-pkgscan-e2e-julia\x00" + name))
	b := sum[:16]
	b[6] = b[6]&0x0f | 0x50 // version 5
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// juliaTreeHash returns the git-tree-sha1 of the tree the members make up: the
// SHA-1 of the Git tree object `git write-tree` would record for those files.
//
// Git hashes a file as the object "blob <size>\x00<content>" and a directory as
// "tree <size>\x00" followed by one "<mode> <name>\x00<20-byte hash>" entry per
// child — mode 100644 for a file, 100755 for an executable, 40000 for a
// directory — ordered by name, a directory's name compared as if it ended in
// "/". Directories exist only as the parents of files: Git records no empty
// tree.
func juliaTreeHash(members []member) string {
	root := juliaNewDir()
	for _, m := range members {
		parts := strings.Split(m.Name, "/")
		dir := root
		for _, p := range parts[:len(parts)-1] {
			sub, ok := dir.dirs[p]
			if !ok {
				sub = juliaNewDir()
				dir.dirs[p] = sub
			}
			dir = sub
		}
		mode := "100644"
		if m.Mode&0o111 != 0 {
			mode = "100755"
		}
		dir.files[parts[len(parts)-1]] = juliaGitEntry{mode: mode, hash: juliaGitObject("blob", []byte(m.Data))}
	}
	return hex.EncodeToString(root.hash())
}

// juliaDir is one directory of the tree juliaTreeHash builds.
type juliaDir struct {
	dirs  map[string]*juliaDir
	files map[string]juliaGitEntry
}

// juliaGitEntry is a file of a juliaDir: its Git mode and blob hash.
type juliaGitEntry struct {
	mode string
	hash []byte
}

func juliaNewDir() *juliaDir {
	return &juliaDir{dirs: map[string]*juliaDir{}, files: map[string]juliaGitEntry{}}
}

// hash returns the Git tree object hash of the directory.
func (d *juliaDir) hash() []byte {
	type entry struct {
		sortKey, name, mode string
		hash                []byte
	}
	entries := make([]entry, 0, len(d.files)+len(d.dirs))
	for name, f := range d.files {
		entries = append(entries, entry{sortKey: name, name: name, mode: f.mode, hash: f.hash})
	}
	for name, sub := range d.dirs {
		entries = append(entries, entry{sortKey: name + "/", name: name, mode: "40000", hash: sub.hash()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].sortKey < entries[j].sortKey })
	var body bytes.Buffer
	for _, e := range entries {
		body.WriteString(e.mode + " " + e.name + "\x00")
		body.Write(e.hash)
	}
	return juliaGitObject("tree", body.Bytes())
}

// juliaGitObject returns the SHA-1 Git names an object of the given type by.
func juliaGitObject(kind string, content []byte) []byte {
	h := sha1.New()
	fmt.Fprintf(h, "%s %d\x00", kind, len(content))
	h.Write(content)
	return h.Sum(nil)
}
