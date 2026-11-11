package backends

import "testing"

func TestHasDotSegment(t *testing.T) {
	dotted := []string{
		"/..",
		"/.",
		"..",
		".",
		"/a/../b",
		"/a/./b",
		"/a/b/..",
		"/a/b/.",
		"/v2/token/manifests/..",
		"/v2/lib/app/blobs/sha256:abc/referrers/..",
		// A path parameter does not hide one from a servlet container.
		"/a/..;x=1/b",
		"/a/.;jsessionid=1/b",
		"/a/..;/b",
		// Nor does a backslash from a server that treats it as a separator.
		`/a/..\b`,
		`/a\..\b`,
		`\..\`,
		// Nor does a further layer of encoding: these are what "%252e%252e" and
		// "%25252e%25252e" look like after the HTTP server's own decoding.
		"/a/%2e%2e/b",
		"/a/%2E%2E/b",
		"/a/.%2e/b",
		"/a/%2e/b",
		"/a/%252e%252e/b",
		"/a/..%2fb",
		"/a/..%5cb",
		"/a/%2e%2e%3bx/b",
	}
	for _, p := range dotted {
		if !HasDotSegment(p) {
			t.Errorf("HasDotSegment(%q) = false, want true", p)
		}
	}

	clean := []string{
		"",
		"/",
		"/a/b/c",
		"/a/.../b", // three dots is a name, not a relative reference
		"/a/..b/c",
		"/a/b../c",
		"/a/.b/c",
		"/.well-known/terraform.json",
		"/.gitattributes",
		"/@scope/name/-/name-1.0.0.tgz",
		"/github.com/!azure/azure-sdk/@v/v1.0.0.zip",
		"/org/repo.git/info/refs",
		"/v2/library/nginx/manifests/1.27",
		"/v2/library/nginx/blobs/sha256:0000",
		"/simple/demo/",
		"/a;x=1/b",
		"/a/b;..", // the parameter's value is not a segment
		"/pool/main/g/gcc/gcc_12.2.0-14%2Bdeb12u1_amd64.deb",
		"/a/100%/b",      // a stray percent sign is not an escape
		"/a/%zz/b",       // nor is an invalid one
		"/a/%2e%2e%2e/b", // an encoded "..." is still a name
	}
	for _, p := range clean {
		if HasDotSegment(p) {
			t.Errorf("HasDotSegment(%q) = true, want false", p)
		}
	}
}

// Decoding stops after a bounded number of rounds: a path encoded more deeply
// than any real chain of hops decodes is not a dot segment to any of them, and
// the check must not be something a client can make arbitrarily expensive.
func TestHasDotSegmentBoundsDecoding(t *testing.T) {
	// "%2525252e" needs four decodings to become ".".
	deep := "/a/%2525252e%2525252e/b"
	if HasDotSegment(deep) {
		t.Errorf("HasDotSegment(%q) = true: decoded further than the bound", deep)
	}
}
