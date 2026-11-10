//go:build fuzz
// +build fuzz

// Fuzz targets for the Ansible Galaxy pull-through parsers (Task 30, Task 163).
//
// A malicious or compromised upstream registry controls the request path, the
// version-detail JSON (and its "artifact.sha256"), the metadata documents the
// proxy rewrites, and the Location of every redirect it answers. All are parsed
// on the pull path before any content is cached or served, so the parsers must
// never panic, must not allocate without bound, and must fail closed on
// malformed input — and whatever link or redirect the proxy hands a client must
// still address this backend's mount.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/ansible/
package ansible

import (
	"bytes"
	"encoding/json"
	"net/url"
	"path"
	"strings"
	"testing"
)

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

// fuzzRewriters are the mount configurations the link-rewriting targets run
// against: a public URL, none, an upstream beneath a base path, and a public
// URL beneath a path prefix.
func fuzzRewriters(t *testing.T) []*linkRewriter {
	t.Helper()
	return []*linkRewriter{
		testRewriter(t, testUpstream, testPublicBase),
		testRewriter(t, testUpstream, ""),
		testRewriter(t, "https://hub.example.com/galaxy", testPublicBase),
		testRewriter(t, testUpstream, "https://proxy.example.com/pullthrough/v1/ansible"),
	}
}

// insideMount reports whether a rewritten link still addresses the mount once
// a client has resolved it against the proxy and the server has normalised its
// path — the property that keeps a served link or a relayed redirect from
// steering a client past this backend.
func insideMount(lr *linkRewriter, link string) bool {
	ref, err := url.Parse(link)
	if err != nil {
		return false
	}
	proxy := &url.URL{Scheme: "https", Host: "proxy.example.com", Path: lr.mountPath + "/"}
	target := proxy.ResolveReference(ref)
	if target.Host != proxy.Host {
		return false
	}
	clean := path.Clean("/" + target.Path)
	return clean == lr.mountPath || strings.HasPrefix(clean, lr.mountPath+"/")
}

func FuzzRewriteDocument(f *testing.F) {
	f.Add([]byte(`{"a":"https://galaxy.ansible.com/x","b":"./rel"}`))
	f.Add([]byte(`["https://galaxy.ansible.com/x",{"c":"https://galaxy.ansible.com/y"}]`))
	f.Add([]byte(docCollection))
	f.Add([]byte(docVersions))
	f.Add([]byte(docVersionDetail))
	f.Add([]byte(docV1Root))
	f.Add([]byte(docV1Roles))
	f.Add([]byte(`{"href":"/api/v3/x/","big":12345678901234567890,"float":1.0,"/api/v3/key/":"/tmp"}`))
	f.Add([]byte(`{"next":"/api/v3/x/?limit=10&offset=10","up":"/api/../admin/","enc":"/api/%2e%2e/admin/"}`))
	f.Add([]byte(`{"href":"/galaxy/api/v3/x/","abs":"https://hub.example.com/galaxy/api/v3/y.tar.gz"}`))
	f.Add([]byte(`"/api/v3/x/"`))
	f.Add([]byte(`{"href":"/api/v3/x/"} trailing`))
	f.Add([]byte(`[[[[[[[[[["/api/v3/deep/"]]]]]]]]]]`))
	f.Add([]byte("not json"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, body []byte) {
		for _, lr := range fuzzRewriters(t) {
			out, changed := lr.rewriteDocument(body)
			if !changed {
				if !bytes.Equal(out, body) {
					t.Fatalf("unchanged document was altered: %q -> %q", body, out)
				}
				continue
			}
			if !json.Valid(out) {
				t.Fatalf("rewritten document is not JSON: %q -> %q", body, out)
			}
			// A served document holds no upstream link, so rewriting it again is a no-op.
			if again, changed := lr.rewriteDocument(out); changed {
				t.Fatalf("rewrite is not idempotent: %q -> %q -> %q", body, out, again)
			}
		}
	})
}

func FuzzRewriteValue(f *testing.F) {
	for _, s := range []string{
		"/api/v3/plugin/ansible/content/published/collections/index/community/general/versions/?limit=10&offset=10",
		"/api/content/published/v3/plugin/ansible/content/published/collections/index/community/general/",
		"https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/artifacts/community-general-8.0.0.tar.gz",
		"http://galaxy.ansible.com/api/v1/roles/?page=2&page_size=2",
		"https://galaxy.ansible.com:443/api/v3/",
		"HTTPS://GALAXY.ANSIBLE.COM/API/",
		"https://galaxy.ansible.com",
		"https://galaxy.ansible.com?x=1#f",
		"https://galaxy.ansible.com.evil.example/api/v3/",
		"https://user@galaxy.ansible.com/api/v3/",
		"https://hub.example.com/galaxy/api/v3/",
		"/galaxy/api/v3/?offset=10",
		"/galaxy",
		"/api/../admin/api/cache",
		"/api/%2e%2e/%2E%2E/admin/",
		"/api/..%2f..%2fadmin/",
		"/api/v3/..\\..\\admin",
		"/api/v3/100%/",
		"/api/v3/ is prose",
		"/api/v3/\r\nSet-Cookie: x=1",
		"//galaxy.ansible.com/api/v3/",
		"/usr/local/bin",
		"/api",
		"/api/",
		"/",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, lr := range fuzzRewriters(t) {
			out, ok := lr.rewriteValue(s)
			if !ok {
				if out != s {
					t.Fatalf("rejected value was altered: %q -> %q", s, out)
				}
				continue
			}
			if !isCleanRef(out) {
				t.Fatalf("rewritten link holds whitespace or a control character: %q -> %q", s, out)
			}
			if !strings.HasPrefix(out, lr.publicBase) && !strings.HasPrefix(out, lr.mountPath) {
				t.Fatalf("rewritten link is not anchored at the mount: %q -> %q", s, out)
			}
			if !insideMount(lr, out) {
				t.Fatalf("rewritten link leaves the mount: %q -> %q", s, out)
			}
		}
	})
}

func FuzzLocation(f *testing.F) {
	const req = "https://galaxy.ansible.com/api/v3/collections/community/general/versions/?limit=100"
	for _, s := range []string{
		"/api/v3/plugin/ansible/content/published/collections/index/community/general/versions/?limit=100",
		"/api/",
		"https://galaxy.ansible.com/api/pulp/content/published/community-general-8.0.0.tar.gz?expires=1&validate_token=a:b",
		"http://galaxy.ansible.com/api/v3/",
		"//galaxy.ansible.com/api/v3/",
		"//evil.example/api/v3/",
		"https://ansible-galaxy-ng.s3.dualstack.us-east-1.amazonaws.com/artifact/74/db5d?X-Amz-Signature=x",
		"https://galaxy.ansible.com.evil.example/api/",
		"https://user:pw@galaxy.ansible.com/api/",
		"8.0.0/",
		"../",
		"../../../../../../../admin/api/cache",
		"?limit=100&offset=100",
		"/api/%2e%2e/%2e%2e/admin/api/cache",
		"/api/..%2f..%2fadmin/",
		"/api/..\\..\\admin/",
		"/api/\r\nSet-Cookie: x=1",
		"/api/%zz/",
		"/galaxy/api/v3/",
		"https://hub.example.com/galaxy/api/v3/",
		"javascript:alert(1)",
		"mailto:root@galaxy.ansible.com",
		"  /api/  ",
		"",
	} {
		f.Add(req, s)
	}
	f.Add("https://hub.example.com/galaxy/api/v3/collections/a/b/", "../../../../../../login")
	f.Add("://not a url", "/api/")
	f.Fuzz(func(t *testing.T, requestURL, location string) {
		for _, lr := range fuzzRewriters(t) {
			out, ok := lr.location(requestURL, location)
			if !ok {
				if out != "" {
					t.Fatalf("refused redirect still yielded a location: %q -> %q", location, out)
				}
				continue
			}
			if !isCleanRef(out) {
				t.Fatalf("relayed Location holds whitespace or a control character: %q -> %q", location, out)
			}
			if !strings.HasPrefix(out, lr.publicBase) && !strings.HasPrefix(out, lr.mountPath) {
				t.Fatalf("relayed Location is not anchored at the mount: %q -> %q", location, out)
			}
			if !insideMount(lr, out) {
				t.Fatalf("relayed Location leaves the mount: %q (for %q) -> %q", location, requestURL, out)
			}
		}
	})
}
