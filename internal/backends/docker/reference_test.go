package docker

import "testing"

func TestParseReference(t *testing.T) {
	const dig = "sha256:" + "ab12cd34" + "ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34" // 64 hex

	cases := []struct {
		name      string
		path      string
		wantOK    bool
		kind      refKind
		repo      string
		reference string
		isDigest  bool
		scope     string
	}{
		{
			name:   "ping",
			path:   "/v2/",
			wantOK: true,
			kind:   refPing,
		},
		{
			name:   "ping no trailing slash",
			path:   "/v2",
			wantOK: true,
			kind:   refPing,
		},
		{
			name:      "manifest by tag",
			path:      "/v2/library/nginx/manifests/latest",
			wantOK:    true,
			kind:      refManifest,
			repo:      "library/nginx",
			reference: "latest",
			isDigest:  false,
			scope:     "repository:library/nginx:pull",
		},
		{
			name:      "manifest by digest",
			path:      "/v2/library/nginx/manifests/" + dig,
			wantOK:    true,
			kind:      refManifest,
			repo:      "library/nginx",
			reference: dig,
			isDigest:  true,
			scope:     "repository:library/nginx:pull",
		},
		{
			name:      "blob by digest",
			path:      "/v2/library/nginx/blobs/" + dig,
			wantOK:    true,
			kind:      refBlob,
			repo:      "library/nginx",
			reference: dig,
			isDigest:  true,
			scope:     "repository:library/nginx:pull",
		},
		{
			name:      "deeply nested repository name",
			path:      "/v2/org/team/sub/repo/manifests/v1.2.3",
			wantOK:    true,
			kind:      refManifest,
			repo:      "org/team/sub/repo",
			reference: "v1.2.3",
			scope:     "repository:org/team/sub/repo:pull",
		},
		{
			name:   "tags list recovers repo for scope",
			path:   "/v2/library/nginx/tags/list",
			wantOK: true,
			kind:   refOther,
			repo:   "library/nginx",
			scope:  "repository:library/nginx:pull",
		},
		{
			name:   "catalog",
			path:   "/v2/_catalog",
			wantOK: true,
			kind:   refOther,
		},
		{
			name:   "a repository may be called like a token endpoint",
			path:   "/v2/token/tags/list",
			wantOK: true,
			kind:   refOther,
			repo:   "token",
			scope:  "repository:token:pull",
		},
		{
			name:   "blob upload path is not a pull resource",
			path:   "/v2/library/nginx/blobs/uploads/uuid-1234",
			wantOK: false,
		},
		{
			name:   "blob upload session start is not a pull resource",
			path:   "/v2/library/nginx/blobs/uploads/",
			wantOK: false,
		},
		// Registry-hosted token endpoints, and anything else that is not a read
		// endpoint of the distribution API, are refused (see
		// TestTokenEndpointsAreNeverForwarded).
		{name: "artifactory/nexus token endpoint", path: "/v2/token", wantOK: false},
		{name: "quay token endpoint", path: "/v2/auth", wantOK: false},
		{name: "unknown registry-level endpoint", path: "/v2/users/login", wantOK: false},
		{name: "catalog with a suffix", path: "/v2/_catalog/extra", wantOK: false},
		{name: "bare repository", path: "/v2/library/nginx", wantOK: false},
		{name: "tag list without a repository", path: "/v2/tags/list", wantOK: false},
		{
			name:   "non-v2 path rejected",
			path:   "/v1/something",
			wantOK: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ref, ok := parseReference(c.path)
			if ok != c.wantOK {
				t.Fatalf("parseReference(%q) ok = %v, want %v", c.path, ok, c.wantOK)
			}
			if !ok {
				return
			}
			if ref.kind != c.kind {
				t.Errorf("kind = %v, want %v", ref.kind, c.kind)
			}
			if ref.name != c.repo {
				t.Errorf("name = %q, want %q", ref.name, c.repo)
			}
			if ref.reference != c.reference {
				t.Errorf("reference = %q, want %q", ref.reference, c.reference)
			}
			if ref.isDigest != c.isDigest {
				t.Errorf("isDigest = %v, want %v", ref.isDigest, c.isDigest)
			}
			if ref.scope() != c.scope {
				t.Errorf("scope = %q, want %q", ref.scope(), c.scope)
			}
		})
	}
}
