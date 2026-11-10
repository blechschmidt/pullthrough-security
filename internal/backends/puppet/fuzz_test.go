//go:build fuzz
// +build fuzz

// Fuzz targets for the Puppet Forge pull-through parsers (Task 30, Task 163).
//
// A malicious or compromised upstream registry controls the request path, the
// release-metadata JSON (and its "file_sha256"/"file_md5"), and the metadata
// documents the proxy rewrites. All are parsed on the pull path before any
// content is cached or served, so the parsers must never panic, must not
// allocate without bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/puppet/
package puppet

import "testing"

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/v3/files/puppetlabs-stdlib-9.4.1.tar.gz",
		"/v3/files/owner1-mod_name-2.0.0-rc1.tar.gz",
		"/v3/releases/puppetlabs-stdlib-9.4.1",
		"/v3/modules/puppetlabs-stdlib",
		"/v3/files/../x.tar.gz",
		"/v3/modules", "", "/", "////",
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
			if res.owner == "" || res.name == "" || res.version == "" || res.releaseSlug() == "" {
				t.Fatalf("artifact with incomplete coordinate: %q -> %+v", path, res)
			}
		}
	})
}

func FuzzParseReleaseMeta(f *testing.F) {
	f.Add([]byte(`{"file_uri":"/v3/files/x.tar.gz","file_sha256":"abcd","file_md5":"ef01"}`))
	f.Add([]byte(`{"file_md5":"ef01"}`))
	f.Add([]byte("not json"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, body []byte) {
		rm, err := parseReleaseMeta(body)
		if err != nil {
			return
		}
		if c, ok := rm.checksum(); ok {
			switch c.algo {
			case algoSHA256:
				if len(c.hex) != sha256HexLen || !isHex(c.hex) {
					t.Fatalf("checksum returned a non-sha256 digest: %q", c.hex)
				}
			case algoMD5:
				if len(c.hex) != md5HexLen || !isHex(c.hex) {
					t.Fatalf("checksum returned a non-md5 digest: %q", c.hex)
				}
			default:
				t.Fatalf("checksum returned an unknown algo: %q", c.algo)
			}
		}
	})
}

func FuzzRewriteMetadata(f *testing.F) {
	f.Add([]byte(`{"a":"https://forgeapi.puppet.com/x","b":"/v3/files/rel.tar.gz"}`))
	f.Add([]byte(`["https://forgeapi.puppet.com/x",{"c":"https://forgeapi.puppet.com/y"}]`))
	f.Add([]byte("not json"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = rewriteMetadata(body, "https://forgeapi.puppet.com", "https://proxy/v1/puppet")
	})
}
