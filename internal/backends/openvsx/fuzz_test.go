package openvsx

import (
	"strings"
	"testing"
)

// FuzzParseSHA256Sidecar exercises the sidecar parser over arbitrary upstream
// bytes. It must never panic and must only report ok for a well-formed 64-hex
// digest; whenever it reports ok the returned token must itself re-parse to the
// same value (idempotent) and be exactly 64 lowercase hex characters.
func FuzzParseSHA256Sidecar(f *testing.F) {
	f.Add(strings.Repeat("a", 64))
	f.Add("sha256:" + strings.Repeat("0", 64))
	f.Add(strings.Repeat("A", 64) + "  file.vsix\n")
	f.Add("")
	f.Add("not a digest")
	f.Fuzz(func(t *testing.T, s string) {
		got, ok := parseSHA256Sidecar([]byte(s))
		if !ok {
			return
		}
		if len(got) != sha256HexLen || !isHex(got) || got != strings.ToLower(got) {
			t.Fatalf("parseSHA256Sidecar(%q) returned malformed digest %q", s, got)
		}
		again, ok2 := parseSHA256Sidecar([]byte(got))
		if !ok2 || again != got {
			t.Fatalf("parse not idempotent for %q: (%q,%v)", got, again, ok2)
		}
	})
}

// FuzzClassify exercises the path classifier over arbitrary inputs. It must
// never panic, and a classified .vsix must always expose a non-empty version and
// extension id built from safe (traversal-free) segments.
func FuzzClassify(f *testing.F) {
	f.Add("/api/ns/ext")
	f.Add("/api/ns/ext/1.0.0/file/ns.ext-1.0.0.vsix")
	f.Add("/api/ns/ext/plat/1.0.0/file/ns.ext-plat-1.0.0.vsix")
	f.Add("/vscode/gallery/extensionquery")
	f.Add("/api/../../etc/passwd")
	f.Fuzz(func(t *testing.T, path string) {
		res, ok := classify(path)
		if !ok {
			return
		}
		if res.kind == kindVsix {
			if res.version == "" || res.extID == "" {
				t.Fatalf("classify(%q) vsix missing coordinate: %+v", path, res)
			}
			for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
				if seg == "" || seg == "." || seg == ".." {
					t.Fatalf("classify(%q) accepted an unsafe segment", path)
				}
			}
		}
	})
}
