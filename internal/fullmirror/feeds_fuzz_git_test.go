//go:build fuzz
// +build fuzz

// Fuzz targets for the Git-backed feeds' protocol and object parsers (Task
// 190): the ref advertisement, the fetch response, packs and their deltas,
// commits and trees all come from the registry's Git server. They must never
// panic, never allocate without bound, and fail closed.
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzGitPack$' ./internal/fullmirror/
package fullmirror

import (
	"bytes"
	"os"
	"testing"
)

func FuzzGitCapabilities(f *testing.F) {
	seedFiles(f, "git", "info-refs.bin")
	f.Add([]byte("000eversion 2\n0000"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseGitCapabilities(data)
	})
}

func FuzzGitLsRefs(f *testing.F) {
	seedFiles(f, "git", "ls-refs.bin")
	f.Add([]byte("0011unborn HEAD\n0000"))
	f.Fuzz(func(t *testing.T, data []byte) {
		refs, err := parseLsRefs(bytes.NewReader(data))
		if err != nil {
			return
		}
		for ref, oid := range refs {
			if !isHexOID(oid) {
				t.Fatalf("ref %q names %q", ref, oid)
			}
		}
	})
}

func FuzzGitFetchResponse(f *testing.F) {
	seedFiles(f, "git", "fetch-incremental.bin")
	f.Add(append(pktLine("packfile\n"), pktFlush...))
	f.Fuzz(func(t *testing.T, data []byte) {
		pack, err := readFetchResponse(bytes.NewReader(data), 1<<20)
		if err != nil {
			return
		}
		if len(pack) > 1<<20 {
			t.Fatalf("a pack past its bound: %d bytes", len(pack))
		}
		_, _ = parsePack(pack)
	})
}

func FuzzGitPack(f *testing.F) {
	if data, err := os.ReadFile("testdata/feeds/git/fetch-incremental.bin"); err == nil {
		if pack, err := readFetchResponse(bytes.NewReader(data), maxGitPack); err == nil {
			f.Add(pack)
		}
	}
	f.Add(buildTestPack([]gitObject{{typ: gitTree, data: []byte("100644 a\x00" + string(make([]byte, 20)))}, {typ: gitTree, data: []byte("100644 b\x00" + string(make([]byte, 20)))}}, true))
	f.Fuzz(func(t *testing.T, data []byte) {
		objs, err := parsePack(data)
		if err != nil {
			return
		}
		for id, o := range objs.objs {
			if hashObject(o.typ, o.data) != id {
				t.Fatalf("object %s is indexed under the wrong id", id)
			}
		}
	})
}

func FuzzGitDelta(f *testing.F) {
	f.Add([]byte("0123456789"), []byte{10, 4, 0x91, 2, 4})
	f.Add([]byte("abc"), makeDelta([]byte("abc"), []byte("abcdef")))
	f.Fuzz(func(t *testing.T, base, delta []byte) {
		out, err := applyDelta(base, delta)
		if err == nil && len(out) > maxGitObject {
			t.Fatalf("a delta built %d bytes", len(out))
		}
	})
}

func FuzzGitTreeAndCommit(f *testing.F) {
	f.Add([]byte("100644 README.md\x00" + string(make([]byte, 20)) + "40000 pkgs\x00" + string(make([]byte, 20))))
	f.Add([]byte("tree 4410f9ba1bf91c2edae641c93b511f3010ded389\ncommitter A <a@b> 1700000000 +0000\n\nmsg"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if entries, err := parseGitTree(data); err == nil {
			for _, e := range entries {
				if e.name == "" || e.name == "." || e.name == ".." || bytes.ContainsAny([]byte(e.name), "/\x00") {
					t.Fatalf("accepted entry name %q", e.name)
				}
			}
		}
		_, _ = parseGitCommit(data)
	})
}

func FuzzCargoIndexFile(f *testing.F) {
	seedFiles(f, "cargo", "index-cfg-if.jsonl", "index-serde_derive.jsonl")
	f.Add([]byte(`{"name":"a","vers":"1.0.0/../x"}` + "\n" + `{"name":"a","vers":"1.0.0","yanked":true,"pubtime":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := parseCargoIndexFile(data)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !isCrateName(e.Name) || !cleanName(e.Version) {
				t.Fatalf("accepted entry %+v", e)
			}
		}
	})
}
