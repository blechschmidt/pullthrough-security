//go:build fuzz
// +build fuzz

// Fuzz targets for the Ansible Galaxy pull-through parsers (Task 30, Task 163).
//
// A malicious or compromised upstream registry controls the request path, the
// version-detail JSON (and its "artifact.sha256"), and the metadata documents
// the proxy rewrites. All are parsed on the pull path before any content is
// cached or served, so the parsers must never panic, must not allocate without
// bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/ansible/
package ansible

import "testing"

func FuzzClassify(f *testing.F) {
	seeds := []string{
		artPrefix + "/community-general-8.0.0.tar.gz",
		artPrefix + "/my_ns-my_coll-1.0.0-rc1.tar.gz",
		indexPrefix + "/community/general/versions/8.0.0/",
		artPrefix + "/../x.tar.gz",
		"/api/v1/roles/", "", "/", "////",
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
		_ = res.coordinateName()
		if res.kind == kindArtifact {
			if res.namespace == "" || res.name == "" || res.version == "" || res.indexBase == "" {
				t.Fatalf("artifact with incomplete coordinate: %q -> %+v", path, res)
			}
		}
	})
}

func FuzzParseVersionDetail(f *testing.F) {
	f.Add([]byte(`{"artifact":{"sha256":"abcd","size":3,"filename":"x.tar.gz"},"download_url":"https://galaxy.ansible.com/x"}`))
	f.Add([]byte(`{"artifact":{}}`))
	f.Add([]byte("not json"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, body []byte) {
		vd, err := parseVersionDetail(body)
		if err != nil {
			return
		}
		if h, ok := vd.sha256(); ok {
			if len(h) != sha256HexLen || !isHex(h) {
				t.Fatalf("sha256 returned a non-sha256 digest: %q", h)
			}
		}
	})
}

func FuzzNormalizeSHA256(f *testing.F) {
	f.Add("abcd")
	f.Add("sha256:deadbeef")
	f.Add("md5:deadbeef")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		if h, ok := normalizeSHA256(s); ok {
			if len(h) != sha256HexLen || !isHex(h) {
				t.Fatalf("normalizeSHA256 accepted a non-sha256 digest: %q -> %q", s, h)
			}
		}
	})
}

func FuzzRewriteMetadata(f *testing.F) {
	f.Add([]byte(`{"a":"https://galaxy.ansible.com/x","b":"./rel"}`))
	f.Add([]byte(`["https://galaxy.ansible.com/x",{"c":"https://galaxy.ansible.com/y"}]`))
	f.Add([]byte("not json"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = rewriteMetadata(body, "https://galaxy.ansible.com", "https://proxy/v1/ansible")
	})
}
