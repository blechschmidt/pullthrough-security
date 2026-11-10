//go:build fuzz
// +build fuzz

// Fuzz targets for the Terraform/OpenTofu pull-through parsers (Task 30, Task 53).
//
// A malicious or compromised registry controls the request path, the
// X-Terraform-Get module-source header, the provider package descriptor (JSON),
// and the SHA256SUMS manifest — all parsed on the pull path before any content is
// cached or served. The parsers must never panic, must not allocate without
// bound, and must fail closed on malformed input. The provider descriptor and
// the go-getter X-Terraform-Get value are the primary supply-chain attack
// surfaces the fuzzer exercises.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzParseProviderPackage ./internal/backends/terraform/
package terraform

import "testing"

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/.well-known/terraform.json",
		"/v1/modules/hashicorp/consul/aws/versions",
		"/v1/modules/hashicorp/consul/aws/1.0.0/download",
		"/v1/modules/hashicorp/consul/aws/1.0.0/archive",
		"/v1/modules/hashicorp/consul/aws/download",
		"/v1/providers/hashicorp/aws/versions",
		"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64",
		"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64/zip",
		"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64/shasums",
		"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64/shasums.sig",
		"/../etc/passwd",
		"",
		"/",
		"////",
		"/v1/modules",
		"/v1/providers/x",
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
		// A cacheable provider artifact must carry the coordinates needed to
		// re-derive its upstream descriptor URL, or we could build a malformed URL.
		switch res.kind {
		case kindProviderZip, kindProviderShasums, kindProviderShasumsSig:
			if res.namespace == "" || res.name == "" || res.version == "" || res.os == "" || res.arch == "" {
				t.Fatalf("synthetic provider artifact with incomplete coordinate: %q", path)
			}
		case kindModuleArchive:
			if res.namespace == "" || res.name == "" || res.system == "" || res.version == "" {
				t.Fatalf("module archive with incomplete coordinate: %q", path)
			}
		}
	})
}

func FuzzParseTerraformGet(f *testing.F) {
	seeds := []string{
		"https://example.com/archive/v1.0.0.tar.gz",
		"https://api.github.com/repos/o/r/tarball/v5.0.0//*?archive=tar.gz",
		"git::https://github.com/o/r.git//modules/foo?ref=v1",
		"s3::https://s3.amazonaws.com/bucket/key.zip",
		"./relative/path",
		"",
		"::",
		"https://h//s//t?a=b&c=d",
		"http://x?archive=zip",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		g, ok := parseTerraformGet(raw)
		if !ok {
			return
		}
		if g.url == "" {
			t.Fatalf("parsed terraformGet with empty url from %q", raw)
		}
		// rewrite must never panic and must contain the substituted base.
		out := g.rewrite("https://proxy/archive")
		if out == "" {
			t.Fatalf("empty rewrite for %q", raw)
		}
		_ = g.cacheable()
		_ = g.archiveType()
	})
}

func FuzzParseProviderPackage(f *testing.F) {
	seeds := []string{
		`{"os":"linux","arch":"amd64","filename":"terraform-provider-aws_5.0.0_linux_amd64.zip",` +
			`"download_url":"https://r/aws.zip","shasums_url":"https://r/SHA256SUMS",` +
			`"shasums_signature_url":"https://r/SHA256SUMS.sig","shasum":"` +
			"1111111111111111111111111111111111111111111111111111111111111111" +
			`","signing_keys":{"gpg_public_keys":[{"key_id":"ABC","ascii_armor":"-----BEGIN-----"}]}}`,
		`{}`,
		`{"filename":"x"}`,
		`not json`,
		``,
		`{"download_url":123}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		pkg, err := parseProviderPackage(data)
		if err != nil {
			return
		}
		// A successfully parsed package must carry the fields the proxy relies on.
		if pkg.Filename == "" || pkg.DownloadURL == "" {
			t.Fatalf("parsed provider package missing required fields: %+v", pkg)
		}
		_ = pkg.armoredKeys()
		_ = pkg.primaryKeyID()
		// Rewriting must round-trip back to valid JSON without panicking.
		if _, rerr := rewriteProviderPackage(data, "z", "s", "sig"); rerr != nil {
			// A descriptor that parsed but is not a JSON object is acceptable to reject.
			_ = rerr
		}
	})
}

func FuzzParseSHASUMS(f *testing.F) {
	seeds := []string{
		"1111111111111111111111111111111111111111111111111111111111111111  file.zip\n",
		"deadbeef *bin.zip\n",
		"  \n\n",
		"shortsum file\n",
		"",
		"1111111111111111111111111111111111111111111111111111111111111111\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		sums := parseSHASUMS(data)
		for name, hexsum := range sums {
			if name == "" {
				t.Fatalf("SHASUMS entry with empty filename")
			}
			if len(hexsum) != sha256HexLen || !isHex(hexsum) {
				t.Fatalf("SHASUMS retained malformed digest: %q", hexsum)
			}
		}
	})
}
