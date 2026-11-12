//go:build fuzz
// +build fuzz

// Fuzz targets for the personal-link edge (Task 177).
//
// The edge rewrites text it did not write — index documents from upstream
// registries, with whatever a package author put into a README — and it does so
// on the path of a credential. Two properties must hold for every input:
//
//   - the rewriter only ever inserts the personal prefix directly in front of
//     the mount path, nothing else is changed, added or dropped, and the result
//     does not depend on how the stream was cut into chunks;
//   - a request path, whatever it contains, is never written down with a
//     link's token in it.
//
// Run one with:
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzLinkRewriter$' -fuzztime=30s ./internal/proxy/
package proxy

import (
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/userlinks"
)

// What the rewriter guarantees whatever it is fed: it only ever inserts the
// personal prefix directly in front of the mount path, and the result does not
// depend on how the input was cut into chunks.
func FuzzLinkRewriter(f *testing.F) {
	f.Add(`{"tarball":"https://proxy.example.com/v1/npm/a/-/a-1.tgz"}`, uint8(7), true)
	f.Add(`"/v1/npm/a" /v1/npm`, uint8(1), false)
	f.Add(`https://proxy.example.com/v1/npm`, uint8(3), true)
	f.Add("/v1/np", uint8(2), false)
	f.Add(strings.Repeat("/v1/npm", 20), uint8(5), true)
	f.Add(`"https://proxy.example.com`+testPrefix+`/v1/npm/a"`, uint8(9), false)
	f.Add("\"/proxy/v1/npm/x\" /v1/npm\x00/v1/npm/", uint8(4), true)
	f.Fuzz(func(t *testing.T, in string, chunk uint8, withPath bool) {
		publicURL := testPublicURL
		if withPath {
			publicURL += "/proxy"
		}
		const mount = "/v1/npm"
		whole := newLinkRewriter(mount, testPrefix, publicURL, "proxy.example.com:8443").rewriteAll(in)

		// Taking the inserted prefixes out again gives back the input: nothing
		// else was changed, added or dropped.
		collapse := func(s string) string { return strings.ReplaceAll(s, testPrefix+mount, mount) }
		if collapse(whole) != collapse(in) {
			t.Fatalf("the rewriter changed more than the links\n in  %q\n out %q", in, whole)
		}
		if len(whole) < len(in) || (len(whole)-len(in))%len(testPrefix) != 0 {
			t.Fatalf("the output is not the input plus whole prefixes: %d → %d bytes", len(in), len(whole))
		}

		size := int(chunk)%17 + 1
		rw := newLinkRewriter(mount, testPrefix, publicURL, "proxy.example.com:8443")
		var out []byte
		for i := 0; i < len(in); i += size {
			out = append(out, rw.feed([]byte(in[i:min(i+size, len(in))]), false)...)
		}
		out = append(out, rw.feed(nil, true)...)
		if string(out) != whole {
			t.Fatalf("chunks of %d give a different result\n in    %q\n whole %q\n parts %q", size, in, whole, out)
		}
	})
}

// A personal path is never written down with its token: whatever stands where
// the token goes is replaced, and the rest of the path is kept.
func FuzzRedactPersonalPath(f *testing.F) {
	tok, _ := userlinks.NewToken()
	f.Add("/u/"+tok+"/v1/npm/lodash", "/u")
	f.Add("/v2/u/"+tok+"/dockerhub/library/alpine/manifests/3.19", "/u")
	f.Add("/v1/npm/lodash", "/u")
	f.Add("/u/", "/u")
	f.Add("/u//x", "/me")
	f.Add("/me/"+tok, "/me")
	f.Add("/u/"+tok+"/v2/u/"+tok+"/a/manifests/1", "/u")
	f.Add("/v2/u/ptl1short/a/manifests/1", "/u")
	f.Fuzz(func(t *testing.T, path, prefix string) {
		got := redactPersonalPath(path, prefix)
		if prefix == "" {
			if got != path {
				t.Fatalf("with the feature off, %q became %q", path, got)
			}
			return
		}
		// Whatever the path, nothing that starts like a token survives — the
		// property that matters, stated without the code's own logic.
		for _, part := range strings.Split(got, "/") {
			if strings.HasPrefix(part, userlinks.TokenPrefix) {
				t.Fatalf("redactPersonalPath(%q, %q) = %q keeps %q", path, prefix, got, part)
			}
		}
		// The component after a leading personal prefix is a token, whatever
		// it looks like.
		if after, ok := strings.CutPrefix(path, prefix+"/"); ok {
			if token, _, _ := strings.Cut(after, "/"); token != "" && !strings.HasPrefix(got, prefix+"/"+redactedLink) {
				t.Fatalf("redactPersonalPath(%q, %q) = %q keeps the token position %q", path, prefix, got, token)
			}
		}
		// A path that holds no token is left as it is.
		if !strings.Contains(path, userlinks.TokenPrefix) && !strings.HasPrefix(path, prefix+"/") && got != path {
			t.Fatalf("a path without a link was changed: %q → %q", path, got)
		}
	})
}
